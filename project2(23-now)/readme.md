# Software-Defined Storage Middleware

This project is a middleware layer for software-defined storage, leveraging FastAPI, CockroachDB, and etcd. It serves as the backbone for managing user authentication, token-based authorization, and system-wide event handling. The project includes optional LDAP integration and a collection of example endpoints and authentication logic located in the `auth` folder.

## Techs

- **FastAPI**: A modern web framework for building APIs with Python.
- **CockroachDB**: A distributed SQL database for scalable, resilient storage solutions.
- **etcd**: A distributed key-value store for configuration management and service discovery.

## Features

- **Authentication**: Supports token-based authentication and optional LDAP flow.
- **Event Handling**: Tracks system start-up events and system-wide activities.
- **Role-Based Access Control**: Fine-grained access control based on user roles and permissions.
  
## Project Structure

- **`main.py`**: Initializes the FastAPI application, sets up middlewares and routers, and handles SSL/TLS certificates.
- **`auth/`**: Contains authentication logic, including token management, session handling, and role-based authorization.
  - Supports both base authentication and LDAP integration.
  - Example endpoints and authentication logic for handling user tokens and sessions.
