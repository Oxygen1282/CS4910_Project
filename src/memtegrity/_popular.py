"""Well-known package names for the typosquat check (``packages.py``).

A curated snapshot (November 2026) of widely used PyPI and npm packages, plus Python
import names that differ from their PyPI names. A name on these lists is never flagged;
a name one or two edits away from one is. To refresh from the registries' download
statistics, see ``docs/BLOCK4.md``.
"""

PYPI = """
requests urllib3 boto3 botocore setuptools certifi idna charset-normalizer typing-extensions
python-dateutil packaging s3transfer six aiobotocore numpy pyyaml pip cryptography fsspec
s3fs attrs pydantic pydantic-core cffi pycparser jmespath google-api-core protobuf wheel rsa
pyasn1 importlib-metadata zipp markupsafe jinja2 platformdirs pandas pytz click filelock
tomli colorama pyjwt jsonschema wrapt virtualenv cachetools googleapis-common-protos pluggy
pytest grpcio sqlalchemy psutil docutils pyparsing tzdata werkzeug h11 httpx httpcore anyio
sniffio exceptiongroup iniconfig yarl multidict frozenlist aiohttp aiosignal async-timeout
soupsieve beautifulsoup4 lxml pillow scipy matplotlib scikit-learn joblib threadpoolctl tqdm
rich pygments markdown-it-py mdurl flask itsdangerous django fastapi starlette uvicorn
gunicorn redis celery kombu psycopg2 psycopg2-binary psycopg pymysql openpyxl xlrd tabulate
toml tomlkit regex decorator isodate pyarrow greenlet more-itertools distlib black mypy
mypy-extensions pathspec ruff flake8 pycodestyle pyflakes isort pylint astroid coverage
pytest-cov tox nox pre-commit identify nodeenv cfgv paramiko bcrypt pynacl websocket-client
websockets tenacity backoff retry simplejson ujson orjson msgpack marshmallow alembic mako
networkx sympy mpmath torch torchvision torchaudio tensorflow keras transformers tokenizers
huggingface-hub safetensors datasets accelerate openai anthropic langchain langchain-core
tiktoken sentencepiece nltk spacy gensim opencv-python imageio scikit-image seaborn plotly
bokeh dash streamlit gradio ipython ipykernel jupyter jupyterlab notebook nbformat nbconvert
traitlets tornado pyzmq prompt-toolkit wcwidth typer docker kubernetes google-auth
google-cloud-storage azure-core azure-storage-blob sentry-sdk structlog loguru python-dotenv
dnspython email-validator requests-oauthlib oauthlib pyopenssl chardet html5lib
webencodings defusedxml markdown mistune sphinx babel pyrsistent ply cython numba llvmlite
pybind11 setuptools-scm hatchling poetry poetry-core flit twine build uv pipenv pytest-mock
pytest-xdist pytest-asyncio hypothesis faker factory-boy freezegun responses requests-mock
moto boto selenium playwright scrapy pyinstaller py sqlmodel typing-inspect annotated-types
jiter distro shellingham pexpect ptyprocess termcolor tzlocal humanize arrow pendulum
xmltodict pycryptodome passlib argon2-cffi gitpython pyodbc pymongo motor elasticsearch
confluent-kafka kafka-python pika grpcio-tools thrift cachecontrol msal jsonpointer jsonpatch
ruamel-yaml pyproject-hooks trove-classifiers keyring secretstorage jeepney pyserial pytz
python-multipart polars duckdb xgboost lightgbm catboost statsmodels shapely geopandas
folium pydub soundfile librosa boto3-stubs types-requests types-pyyaml pyright pywin32
"""

PYTHON_MODULES = """
bs4 yaml pil sklearn cv2 dateutil jwt google attr dotenv git openssl crypto nacl serial zmq
magic docx pptx fitz skimage mpl_toolkits pkg_resources win32api win32con _pytest
"""

NPM = """
react react-dom lodash express axios chalk commander debug moment request async underscore
uuid bluebird yargs glob minimist mkdirp rimraf semver colors color through2 classnames
prop-types webpack babel-core @babel/core typescript eslint prettier jest mocha chai sinon
vue angular @angular/core next nuxt svelte vite rollup esbuild jquery body-parser
cookie-parser cors dotenv morgan mongoose mongodb mysql mysql2 pg sequelize redis ioredis
socket.io ws node-fetch cross-fetch got superagent cheerio puppeteer playwright inquirer ora
boxen figlet nodemon ts-node tslib rxjs zone.js core-js regenerator-runtime fs-extra
graceful-fs chokidar micromatch minimatch picomatch fast-glob globby execa cross-spawn
shelljs dayjs date-fns luxon immutable ramda redux react-redux mobx zustand
styled-components tailwindcss postcss autoprefixer sass less bootstrap @mui/material antd
framer-motion three d3 chart.js marked highlight.js jsonwebtoken bcrypt bcryptjs passport
helmet express-session multer formidable nodemailer winston pino bunyan joi yup zod ajv
validator qs query-string path-to-regexp iconv-lite safe-buffer buffer events util inherits
readable-stream string_decoder once wrappy ms mime mime-types ansi-styles supports-color
has-flag color-convert color-name escape-string-regexp strip-ansi ansi-regex string-width
wrap-ansi cliui y18n yargs-parser camelcase decamelize kind-of is-number to-regex-range
fill-range braces punycode tough-cookie form-data combined-stream delayed-stream asynckit
follow-redirects proxy-from-env electron vitest @types/node @types/react ts-jest babel-jest
@testing-library/react cypress storybook lerna nx turbo pnpm yarn npm node-sass gulp grunt
browserify uglify-js terser cross-env concurrently husky lint-staged @anthropic-ai/sdk
openai langchain discord.js telegraf stripe aws-sdk @aws-sdk/client-s3 firebase
firebase-admin @supabase/supabase-js prisma @prisma/client knex typeorm graphql
apollo-server @apollo/client koa fastify @hapi/hapi @nestjs/core sharp jimp canvas pdfkit
xlsx papaparse csv-parser yaml js-yaml toml ini xml2js sax ejs pug handlebars mustache
nunjucks http-proxy http-server serve live-server open node-cron cron bull agenda
dotenv-expand config nconf convict react-router react-router-dom swr @tanstack/react-query
"""

PYPI = tuple(PYPI.split())
PYTHON_MODULES = tuple(PYTHON_MODULES.split())
NPM = tuple(NPM.split())
