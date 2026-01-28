# Threat Detection Platform

A comprehensive malware analysis system with a Spring Boot backend and React frontend.

## Architecture

- **Backend**: Spring Boot REST API for binary analysis, PE parsing, YARA scanning
- **Frontend**: React + TypeScript web application for file upload and results visualization

## Features

- Binary file upload and analysis
- PE header and section parsing
- Entropy calculation and packed binary detection
- YARA rule matching
- ML-based threat classification
- Interactive results dashboard

## Prerequisites

- Java 21+
- Maven 3.9+
- Node.js 18+
- npm 9+

## Backend Setup

1. Navigate to the Backend directory:
```bash
cd Backend
```

2. Run the Spring Boot application:
```bash
./mvnw spring-boot:run
```

The backend will start on `http://localhost:8080`

## Frontend Setup

1. Navigate to the frontend directory:
```bash
cd frontend
```

2. Install dependencies:
```bash
npm install
```

3. Start the development server:
```bash
npm run dev
```

The frontend will start on `http://localhost:3000`

## Usage

1. Make sure both backend and frontend are running
2. Open your browser to `http://localhost:3000`
3. Upload a binary file (.exe, .dll, .sys)
4. View the comprehensive analysis results including:
   - File metadata
   - Threat classification
   - YARA rule matches
   - PE header information
   - Section-level analysis
   - Entropy scores

## API Endpoints

### Upload File
- **POST** `/api/upload`
- **Content-Type**: `multipart/form-data`
- **Body**: `file` (binary file)
- **Response**: Analysis result JSON

### CI Upload
- **POST** `/api/ci-upload`
- **Content-Type**: `application/json`
- **Body**: `{ "fileName": "sample.exe", "base64File": "..." }`
- **Response**: Analysis result JSON

## Technology Stack

### Backend
- Spring Boot 4.0
- Spring Security
- JPA/Hibernate
- H2 Database
- PortEx (PE parsing)
- Jackson (JSON processing)

### Frontend
- React 18
- TypeScript
- Vite
- Tailwind CSS
- Axios

## Project Structure

```
project/
├── Backend/
│   ├── src/
│   │   ├── main/
│   │   │   ├── java/.../
│   │   │   │   ├── config/       # Security & CORS config
│   │   │   │   ├── controller/   # REST endpoints
│   │   │   │   ├── dto/          # Data transfer objects
│   │   │   │   ├── model/        # JPA entities
│   │   │   │   ├── repository/   # Data access
│   │   │   │   ├── service/      # Business logic
│   │   │   │   └── util/         # Helper utilities
│   │   │   └── resources/
│   │   │       └── application.properties
│   │   └── test/
│   └── pom.xml
└── frontend/
    ├── src/
    │   ├── components/    # React components
    │   ├── services/      # API client
    │   ├── types/         # TypeScript types
    │   ├── App.tsx
    │   └── main.tsx
    ├── package.json
    └── vite.config.ts
```

## Development

The frontend is configured with a Vite proxy to forward `/api` requests to the backend at `localhost:8080`. CORS is enabled on the backend to accept requests from `localhost:3000`.
