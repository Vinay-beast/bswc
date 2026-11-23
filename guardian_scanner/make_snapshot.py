#!/usr/bin/env python3
"""Reconstructed *dependency fields only* from OWASP Juice Shop's public manifests viewed 2026-11-23.
This is NOT a resolved dependency inventory. Authoritative sources:
https://raw.githubusercontent.com/juice-shop/juice-shop/master/package.json
https://raw.githubusercontent.com/juice-shop/juice-shop/master/frontend/package.json
"""
import json
from pathlib import Path

BACKEND_PROD = '''
@ai-sdk/openai-compatible ^2.0.35
@fontsource/roboto ^5.2.9
@simplewebauthn/server ^14.0.3
ai ^6.0.116
beercss ^4.0.19
clarinet ^0.12.6
compression ^1.8.1
config ^3.3.12
cookie-parser ^1.4.7
cookieconsent ^3.1.1
cors ^2.8.5
errorhandler ^1.5.1
ethers ^6.16.0
express ^4.22.1
express-ipfilter ^1.3.2
express-jwt 0.1.3
express-rate-limit ^7.5.1
express-robots-txt ^0.5.0
express-security.txt ^2.0.0
feature-policy ^0.6.0
file-stream-rotator ^1.0.0
file-type ^16.5.4
finale-rest ^1.2.2
hashids ^2.3.0
hbs ^4.2.0
helmet ^4.6.0
html-entities ^1.4.0
i18n ^0.11.1
js-yaml ^3.14.0
jsonwebtoken 0.4.0
libxml2-wasm ^0.7.1
marsdb ^0.6.11
material-icons ^1.13.14
morgan ^1.10.0
multer ^2.4.0
notevil ^1.3.3
otplib ^13.4.0
pdfkit ^0.11.0
prom-client ^15.1.3
proxy-agent ^8.0.2
pug ^3.0.3
sanitize-filename ^1.6.3
sanitize-html 1.4.2
semver ^7.6.3
sequelize ^6.37.3
serve-index ^1.9.1
socket.io ^4.8.4
sqlite3 ^5.1.7
svg-captcha ^1.4.0
swagger-ui-express ^5.0.1
unzipper ^0.12.3
winston ^3.16.0
z85 ^0.0.2
zod ^4.4.3
'''
BACKEND_DEV = '''
@cyclonedx/cyclonedx-npm ^2.0.0||^3.0.0||^4.00
@eslint/js ^9.33.0
@istanbuljs/nyc-config-typescript ^1.0.2
@types/clarinet ^0.12.3
@types/compression ^1.8.1
@types/config ^3.3.5
@types/cookie-parser ^1.4.10
@types/cors ^2.8.19
@types/cross-spawn ^6.0.6
@types/diff ^7.0.1
@types/errorhandler ^1.5.3
@types/exif ^0.6.5
@types/express ^4.17.25
@types/express-jwt ^6.0.4
@types/i18n ^0.12.0
@types/js-yaml ^3.12.10
@types/jsonwebtoken ^8.5.9
@types/jws ^3.2.10
@types/lodash ^4.17.14
@types/morgan ^1.9.9
@types/multer ^1.4.12
@types/node ^26.0.1
@types/pdfkit ^0.10.6
@types/pug ^2.0.10
@types/sanitize-html ^1.27.2
@types/semver ^7.5.8
@types/sequelize ^4.28.20
@types/serve-index ^1.9.4
@types/supertest ^7.2.0
@types/swagger-ui-express ^4.1.6
@types/unzipper ^0.10.10
concurrently ^5.3.0
cypress ^16.2.0
diff ^9.0.0
eslint ^9.39.4
exif ^0.6.0
globals ^17.4.0
neostandard ^0.13.0
nyc ^15.1.0
socket.io-client ^4.8.4
supertest ^7.2.2
tsx ^4.21.0
typescript ^6.0.3
typescript-eslint ^8.57.1
'''
FRONTEND_PROD = '''
@angular/animations ^22.0.1
@angular/build ^22.0.1
@angular/cdk ^22.0.1
@angular/cli ^22.0.1
@angular/common ^22.0.1
@angular/compiler ^22.0.1
@angular/compiler-cli ^22.0.1
@angular/core ^22.0.1
@angular/forms ^22.0.1
@angular/material ^22.0.1
@angular/platform-browser ^22.0.1
@angular/router ^22.0.1
@codemirror/lang-javascript ^6.2.5
@codemirror/lang-json ^6.0.2
@codemirror/lang-yaml ^6.1.2
@codemirror/merge ^6.12.0
@cyclonedx/cyclonedx-esbuild ^1.0.0
@fortawesome/fontawesome-svg-core ~1.2.30
@fortawesome/free-brands-svg-icons ^5.14.0
@fortawesome/free-regular-svg-icons ^5.14.0
@fortawesome/free-solid-svg-icons ^5.14.0
@ngx-translate/core ^17.0.0
@ngx-translate/http-loader ^17.0.0
@simplewebauthn/browser ^14.0.0
@wagmi/core ^0.5.8
angularx-qrcode ^21.0.5
canvas-confetti ^1.9.3
codemirror ^6.0.2
cookieconsent ^3.1.1
ethers ^5.7.2
flag-icons ^6.9.2
font-mfizz ^2.4.1
jwt-decode ^4.0.0
lodash-es ^4.17.21
material-icons ^1.13.14
ng-gallery ^12.0.0
ng2-file-upload ^10.0.0
ngx-window-token ^7.0.0
ngy-cookie ^6.0.0
rxjs 7.8.2
sass ^1.86.3
snarkdown ^1.2.2
socket.io-client ^4.8.4
solidity-browser-compiler ^1.1.0
tslib ^2.5.0
typescript ~6.0.3
zone.js ~0.15.0
'''
FRONTEND_DEV = '''
@angular/language-service ^22.0.1
@eslint/js 9.33.0
@types/express-serve-static-core ^4.17.9
@types/jwt-decode ^2.2.1
@types/node ^26.0.1
@types/socket.io-client ^1.4.33
@vitest/coverage-v8 ^4.1.2
angular-eslint ^22.0.0
esbuild-visualizer ^0.7.0
eslint ^9.33.0
jsdom ^29.0.1
stylelint ^16.10.0
stylelint-config-sass-guidelines ^12.1.0
stylelint-scss ^6.0.0
typescript-eslint ^8.42.0
vitest ^4.1.1
'''

def parse(s):
    out = {}
    for line in s.strip().splitlines():
        name, ver = line.split(' ', 1)
        out[name] = ver
    return out

def main():
    root = Path(__file__).resolve().parent/'snapshots'
    root.mkdir(exist_ok=True)
    manifest_data = [
        ('backend', 'juice-shop', BACKEND_PROD, BACKEND_DEV, 'https://raw.githubusercontent.com/juice-shop/juice-shop/master/package.json'),
        ('frontend', 'frontend', FRONTEND_PROD, FRONTEND_DEV, 'https://raw.githubusercontent.com/juice-shop/juice-shop/master/frontend/package.json')
    ]
    for folder,name, prod,dev,url in manifest_data:
        data = {'name':name,'version':'20.4.0-SNAPSHOT','private':True,
                'dependencies':parse(prod),'devDependencies':parse(dev)}
        if folder=='backend': data['license']='MIT'
        folderpath = root / folder if folder=='frontend' else root; folderpath.mkdir(exist_ok=True)
        (folderpath/'package.json').write_text(json.dumps(data,indent=2,ensure_ascii=False)+'\n')
        print(folder, len(data['dependencies']), 'prod', len(data['devDependencies']), 'dev',url)
    (root/'SOURCE.md').write_text('''# OWASP Juice Shop manifest-derived snapshot\n\nSource: https://github.com/juice-shop/juice-shop (branch `master`, viewed 2026-11-23).\n\n- Backend manifest: https://raw.githubusercontent.com/juice-shop/juice-shop/master/package.json\n- Frontend manifest: https://raw.githubusercontent.com/juice-shop/juice-shop/master/frontend/package.json\n- `.npmrc` has `package-lock=false`.\n\nThese are reconstructed snapshots of ONLY the name, version, `dependencies`, and `devDependencies` fields. They are NOT the complete original manifests, lockfiles, or an installed dependency tree. All dependency versions are *declared version constraints* unless explicitly resolved from an actual lockfile by the main generator. The snapshot does not pin a Git commit and can differ from newer `master` commits.\n''')

if __name__=='__main__': main()
