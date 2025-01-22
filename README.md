## Install python environment   


```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```


## Run the application watch mode
uvicorn main:app --host 0.0.0.0 --port 80 --reload

## Build the Docker image
docker build -t issue-extractor .

## Run the Docker container
docker run -d -p 80:80 issue-extractor



