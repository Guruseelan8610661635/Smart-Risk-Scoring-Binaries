# Setup Guide

This guide walks through setting up a Python development environment and configuring Jenkins to automate builds for the Smart-Risk-Scoring-Binaries project on Windows.

---

# Setup Guide

## Python Environment
- Install Python 3.12
- Create and activate virtualenv
- Install dependencies via requirements.txt

## Jenkins Installation
- Download and install Jenkins
- Run: `java -jar jenkins.war --httpPort=8080`
- Unlock with initialAdminPassword

## GitHub Actions
- Install `act` from https://github.com/nektos/act
- Run `act` to simulate workflows

## Pipeline Scripts
- Jenkinsfile at project root
- GitHub Actions YAML at `.github/workflows/main.yml`

## Lint & Test Integration
- Use `flake8` for linting
- Use `pytest` for testing
- Validate YAML with `yamllint`


## 🐍 Python Environment Setup

1. **Install Python 3.12**
   - Download from [python.org](https://www.python.org/downloads/release/python-3120/)
   - During installation:
     - ✅ Check “Add Python to PATH”
     - ✅ Enable pip and venv options

2. **Verify Installation**
   Open Command Prompt and run:
   ```cmd
   py -3.12 --version
   pip --version

Create Virtual Environment In your project directory:

cmd
py -3.12 -m venv venv
call venv\Scripts\activate

Install Dependencies Ensure your project has a requirements.txt file, then run:

cmd
pip install -r requirements.txt

⚙️ Jenkins Installation & Configuration
Download Jenkins

Visit jenkins.io

Download the .war file for standalone setup

Run Jenkins Locally

cmd
java -jar jenkins.war --httpPort=8080
Unlock Jenkins

Open browser: http://localhost:8080

Locate initialAdminPassword at:

Code
C:\ProgramData\Jenkins\.jenkins\secrets\initialAdminPassword
Install Suggested Plugins

Follow the setup wizard

Create your admin user

🚀 Jenkins Pipeline Setup
Create a New Pipeline Job

Go to Jenkins dashboard → New Item

Name it (e.g., Unsigned_Binary)

Select Pipeline → Click OK

Configure the Pipeline

Scroll to the Pipeline section

Choose Pipeline script

Paste the following:

pipeline {
    agent any
    stages {
        stage('Git Clone') {
            steps {
                git branch: 'main', url: 'https://github.com/Guruseelan8610661635/Smart-Risk-Scoring-Binaries.git'
            }
        }
        stage('Setup & Install') {
            steps {
                bat '''
                "C:\\Users\\arun1\\AppData\\Local\\Programs\\Python\\Python312\\python.exe" -m venv venv
                call venv\\Scripts\\activate
                pip install --upgrade pip
                pip install -r requirements.txt
                pip list
                '''
            }
        }
    }
    post {
        success {
            echo '✅ Build succeeded!'
        }
        failure {
            echo '❌ Build failed. Check console output for details.'
        }
    }
}

Run the Pipeline

Click Build Now

Monitor progress via Console Output

🧪 GitHub Actions (Optional)
Install act CLI

Visit act GitHub page

Download and install for your OS

Simulate Workflows Locally

bash
act
Note: This is only useful if you maintain .github/workflows/main.yml for GitHub Actions. Jenkins does not use this file.

🧹 Lint & Test Integration (Optional)
Install Tools

bash
pip install flake8 pytest yamllint
Run Linting

bash
flake8 .
Run Tests

bash
pytest tests/
Validate YAML

bash
yamllint .github/workflows/

