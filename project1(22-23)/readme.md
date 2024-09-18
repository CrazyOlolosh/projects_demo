# Digital Workspace Project

This project is a digital workspace that provides real-time notifications and end-to-end encrypted chat, supporting both one-on-one conversations and chat rooms. It utilizes Socket.IO and Redis for real-time communication and session management.

## Features

- **Real-Time Notifications**: Immediate alerts and updates for users.
- **End-to-End Encrypted Chat**: Secure messaging for private and group conversations.
- **Task Tracking**: Manage and assign tasks efficiently.
- **Documentation Storage**: Organize and store documents within the workspace.
- **Full-Text Search**: Advanced search capabilities powered by PostgreSQL and Elasticsearch.
- **Cache Management**: Redis-based caching to optimize performance.
- **Third-Party Integrations**:
  - **Analytics**: Data from DevtoDev and AppsFlyer.
  - **Dashboard Creation**: Automated dashboards for data visualization.
  - **Support Ticket Analysis**: Integration with UseDesk for handling support tickets.

## Techs

- **FastAPI**: The core framework for handling API requests.
- **Websockets**: Real-time communication using Socket.IO.
- **Redis**: Used as a cache backend and for storing websocket-related data.
- **Elasticsearch**: Integration for search indexing.
- **Celery**: For managing background tasks.
- **Sentry**: Error monitoring (commented out, but included for future use).
- **APScheduler**: A scheduling library for periodic tasks, with job storage in Redis.
