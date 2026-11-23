"""In-memory dependency graph built from lockfiles and native resolvers.

Node identity is the canonical purl. A purl reached from several projects or
install paths is ONE node with several occurrences. Roots are projects
("project:<path>"); edges carry type (prod|dev|optional|peer), the declared
range and the edge_source (which parser/tool produced the edge).
"""

from __future__ import annotations

from dataclasses import dataclass, field

EDGE_TYPES = ("prod", "dev", "optional", "peer", "contains", "uses")


@dataclass
class GraphBuilder:
    roots: dict[str, dict] = field(default_factory=dict)
    nodes: dict[str, dict] = field(default_factory=dict)
    edges: dict[tuple[str, str], dict] = field(default_factory=dict)
    unresolved: list[dict] = field(default_factory=list)
    # ecosystem -> project ids whose edges came from an authoritative parser
    edge_sources: dict[str, set] = field(default_factory=dict)

    def add_root(self, root_id: str, **attrs) -> None:
        node = self.roots.setdefault(root_id, {"id": root_id, "kind": "project"})
        node.update({k: v for k, v in attrs.items() if v is not None})

    def add_node(self, purl: str, *, name: str, version: str | None, ecosystem: str,
                 occurrence: dict | None = None, source: str | None = None, **attrs) -> dict:
        node = self.nodes.get(purl)
        if node is None:
            node = {"id": purl, "purl": purl, "name": name, "version": version,
                    "ecosystem": ecosystem, "occurrences": [], "declared_in": [], "found_by": []}
            self.nodes[purl] = node
        for k, v in attrs.items():
            if v is not None and node.get(k) in (None, [], ""):
                node[k] = v
        if occurrence and occurrence not in node["occurrences"]:
            node["occurrences"].append(occurrence)
        if source and source not in node["found_by"]:
            node["found_by"].append(source)
        return node

    def add_edge(self, src: str, dst: str, *, type_: str, range_: str | None,
                 edge_source: str, project: str | None = None) -> None:
        if src == dst:
            return
        key = (src, dst)
        existing = self.edges.get(key)
        if existing is None:
            self.edges[key] = {"from": src, "to": dst, "type": type_, "range": range_,
                               "edge_source": edge_source, "projects": [project] if project else []}
            return
        # Keep the "strongest" type when the same edge is declared differently.
        if _rank(type_) < _rank(existing["type"]):
            existing["type"] = type_
            existing["range"] = range_ or existing["range"]
        if project and project not in existing["projects"]:
            existing["projects"].append(project)

    def add_declared(self, purl: str, manifest: str, section: str, range_: str | None) -> None:
        entry = {"manifest": manifest, "section": section, "range": range_}
        node = self.nodes.get(purl)
        if node is not None and entry not in node["declared_in"]:
            node["declared_in"].append(entry)

    def add_unresolved(self, **record) -> None:
        if record not in self.unresolved:
            self.unresolved.append(record)

    def mark_authoritative(self, ecosystem: str, project_id: str) -> None:
        self.edge_sources.setdefault(ecosystem, set()).add(project_id)

    def to_dict(self) -> dict:
        return {
            "roots": list(self.roots.values()),
            "nodes": list(self.nodes.values()),
            "edges": list(self.edges.values()),
            "unresolved": self.unresolved,
            "authoritative": {k: sorted(v) for k, v in self.edge_sources.items()},
        }


def _rank(t: str) -> int:
    return {"prod": 0, "peer": 1, "optional": 2, "dev": 3}.get(t, 4)
