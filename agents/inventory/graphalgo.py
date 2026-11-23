"""Graph algorithms for the inventory: depth, scope, shortest paths, path counts.

All functions are deterministic (adjacency lists are sorted) and iterative
(no recursion limits on deep npm trees).
"""

from __future__ import annotations

from collections import deque

PATH_COUNT_CAP = 1000
SCOPE_ORDER = ("prod", "peer", "optional", "dev")


def adjacency(edges: list[dict]) -> dict[str, list[str]]:
    adj: dict[str, set[str]] = {}
    for e in edges:
        adj.setdefault(e["from"], set()).add(e["to"])
    return {k: sorted(v) for k, v in adj.items()}


def bfs(adj: dict[str, list[str]], start: str) -> tuple[dict[str, int], dict[str, str]]:
    """Distances and BFS parents from `start` (parents give one shortest path)."""
    dist, parent = {start: 0}, {}
    q = deque([start])
    while q:
        u = q.popleft()
        for v in adj.get(u, ()):
            if v not in dist:
                dist[v] = dist[u] + 1
                parent[v] = u
                q.append(v)
    return dist, parent


def path_to(parent: dict[str, str], start: str, target: str) -> list[str]:
    path = [target]
    while path[-1] != start:
        path.append(parent[path[-1]])
    return path[::-1]


def scopes(edges: list[dict], roots: list[str]) -> dict[str, str]:
    """prod if reachable via prod edges only; else peer (prod+peer); else optional; else dev.

    Dev means the node is reachable ONLY through at least one dev edge.
    """
    allowed = {"prod": {"prod"}, "peer": {"prod", "peer"}, "optional": {"prod", "peer", "optional"},
               "dev": {"prod", "peer", "optional", "dev"}}
    result: dict[str, str] = {}
    for scope in SCOPE_ORDER:
        adj: dict[str, list[str]] = {}
        for e in edges:
            if e["type"] in allowed[scope]:
                adj.setdefault(e["from"], []).append(e["to"])
        seen, q = set(roots), deque(roots)
        while q:
            u = q.popleft()
            for v in adj.get(u, ()):
                if v not in seen:
                    seen.add(v)
                    q.append(v)
        for n in seen:
            result.setdefault(n, scope)
    for r in roots:
        result.pop(r, None)
    return result


def strongly_connected(nodes: list[str], adj: dict[str, list[str]]) -> dict[str, int]:
    """Iterative Tarjan: node -> component index."""
    index, low, on_stack, comp = {}, {}, set(), {}
    stack, counter, comp_id = [], 0, 0
    for root in nodes:
        if root in index:
            continue
        work = [(root, 0)]
        while work:
            node, i = work.pop()
            if i == 0:
                index[node] = low[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)
            children = adj.get(node, [])
            recurse = False
            while i < len(children):
                child = children[i]
                i += 1
                if child not in index:
                    work.append((node, i))
                    work.append((child, 0))
                    recurse = True
                    break
                if child in on_stack:
                    low[node] = min(low[node], index[child])
            if recurse:
                continue
            if low[node] == index[node]:
                while True:
                    w = stack.pop()
                    on_stack.discard(w)
                    comp[w] = comp_id
                    if w == node:
                        break
                comp_id += 1
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
    return comp


def path_counts(adj: dict[str, list[str]], comp: dict[str, int], start: str,
                cap: int = PATH_COUNT_CAP) -> dict[int, int]:
    """Number of distinct paths from `start` to every reachable component of the
    cycle-condensed DAG, capped at cap+1 (reported as 'cap+')."""
    cadj: dict[int, set[int]] = {}
    for u, vs in adj.items():
        for v in vs:
            if comp[u] != comp[v]:
                cadj.setdefault(comp[u], set()).add(comp[v])
    src = comp[start]
    # reachable components, then Kahn topological order on that subgraph
    reach, q = {src}, deque([src])
    while q:
        u = q.popleft()
        for v in cadj.get(u, ()):
            if v not in reach:
                reach.add(v)
                q.append(v)
    indeg = {c: 0 for c in reach}
    for u in reach:
        for v in cadj.get(u, ()):
            indeg[v] += 1
    counts = {c: 0 for c in reach}
    counts[src] = 1
    q = deque(sorted(c for c in reach if indeg[c] == 0))
    while q:
        u = q.popleft()
        for v in sorted(cadj.get(u, ())):
            counts[v] = min(cap + 1, counts[v] + counts[u])
            indeg[v] -= 1
            if indeg[v] == 0:
                q.append(v)
    return counts


def fmt_count(n: int, cap: int = PATH_COUNT_CAP) -> int | str:
    return f"{cap}+" if n > cap else n
