# api_gateway

SciX API Gateway, the core API module for SciX

## Getting Started

These instructions will get you a copy of the project up and running in a docker container or on your local machine for development purposes.

### Prerequisites

To run this project, you will need:

- Python 3.6 or higher
- Docker


### Configuration

Before running the project, you should update the configuration in `config.py`. This file contains settings that are necessary for the proper operation of the application, such as database connection information and secret keys. Make sure to replace the placeholders with the actual values.

### Running the application

To start the application, navigate to the project directory in your terminal and run the following command:

```bash
 docker compose up
```

This command will start all the services defined in the docker-compose.yml file. The API should now be running at `http://localhost:5000`.




## Development

### Running the tests

To run the test and see coverage, navigate to the project directory in your terminal and run:

```bash
# setuptools>=58 breaks support for use_2to3 that is used by ConcurrentLogHandler in adsmutils
pip install setuptools==57.5.0 

# Install dependencies
pip install .[dev]

# Run the test and create coverage report
pytest
```


### Running the application

To install and run the application without Docker, navigate to the project directory in your terminal and run the following commands:

```bash
# setuptools>=58 breaks support for use_2to3 that is used by ConcurrentLogHandler in adsmutils
pip install setuptools==57.5.0 

# Install dependencies
pip install .

# Start the application 
python wsgi.py
```

### Database versioning

Database versioning is managed using Alembic. You can upgrade to the latest revision or downgrade to a previous one using the following commands:

```bash
# Upgrade to latest revision
alembic upgrade <revision>

# Downgrade revision
alembic downgrade <revision>

# Create a new revision
alembic revision --autogenerate -m "revision description"
```
