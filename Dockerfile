FROM python:3.12-slim

# Setup the working directory for the container
WORKDIR /app

# Copy the requirements file to the container
COPY ./requirements.txt ./

# Install the Python dependencies using Python
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code to the container
COPY ./ ./

EXPOSE 80

# Setup the command to run when the container starts
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]
