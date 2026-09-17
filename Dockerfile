FROM python:3

WORKDIR /app

COPY . .

RUN pip install uv && uv sync --frozen

CMD [ "uv", "run", "fastapi", "dev", "--host", "0.0.0.0"]