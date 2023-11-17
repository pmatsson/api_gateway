# Use an official Python runtime as a parent image
FROM python:3.10.10

# Set the working directory in the container to /app
WORKDIR /app

# Add the current directory contents into the container at /app
ADD . /app

# setuptools>=58 breaks support for use_2to3 that is used by ConcurrentLogHandler in adsmutils
RUN pip uninstall -y setuptools
RUN pip install setuptools==57.5.0

# Install PostgreSQL adapter
RUN pip install psycopg2-binary==2.8.6

# Install dependencies
RUN pip install .

# Make port 8181 available to the world outside this container
EXPOSE 8181

