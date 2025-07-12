# Example Prompt for Agent Mode App Development

## How to Use copilot-instructions.md

If you have already created a `copilot-instructions.md` file, you do not need to repeat coding standards or best practices in your prompt. The coding agent will automatically follow those instructions.  
**Focus your prompt on your specific requirements, business logic, and any unique constraints.**

---

## Example Prompt for Agent Mode

**Task:**  
Develop a RESTful API for managing products in an inventory system using Spring Boot 3.x and React 18+.

**Requirements:**  
- Backend: Java 21+, Spring Boot 3.x, JPA/Hibernate, MySQL 8+
- Frontend: React 18+, functional components, Context API for state management
- API endpoints: CRUD for products (id, name, description, price, quantity)
- Validation: Ensure all fields are required; price and quantity must be positive numbers
- Error handling: Return appropriate HTTP status codes and error messages
- Security: Basic authentication for API endpoints
- Docker: Provide Dockerfiles for backend and frontend
- Testing: JUnit 5 for backend, React Testing Library for frontend

**Agent Mode Instructions:**  
- Follow all coding standards and patterns from `copilot-instructions.md`
- Label all code blocks with `// AGENT:`
- Start with minimal, working code for backend and frontend, then iterate based on feedback
- After each code block, prompt for testing and feedback
- Include configuration files (application.yml, Dockerfile) as needed
- Suggest next steps after initial implementation

---

## Sample Prompt: Develop Login API Integration

**Task:**  
Develop a REST API endpoint for user login that integrates with an external authentication system.

**Requirements:**  
- Backend: Java 17+, Spring Boot 3.x
- Endpoint: `POST /api/login`
- Request: Accepts username and password as JSON
- Integration: Authenticate credentials by calling an external REST API (provide a placeholder URL)
- Response: On success, return user details and a JWT token; on failure, return appropriate error message and status code
- Security: Do not store passwords; use HTTPS for all communications
- Error handling: Handle network errors, invalid credentials, and unexpected responses from the external system
- Testing: Provide a sample unit test for the login endpoint

**Agent Mode Instructions:**  
- Follow all coding standards and patterns from `copilot-instructions.md`
- Label all code blocks with `// AGENT:`
- Start with minimal, working code for the login endpoint and integration, then iterate based on feedback
- After each code block, prompt for testing and feedback
- Include configuration examples (application.yml) as needed
- Suggest next steps after initial implementation

---

## Workflow

1. Write your prompt focusing on what you want to build, not how to code it.
2. Submit the prompt to the coding agent.
3. The agent will use the `copilot-instructions.md` file for all technical and architectural decisions.
4. Review the agent's output, test the code, and provide feedback for further iterations.

---
