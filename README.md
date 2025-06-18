# Rails 8 + Keycloak Integration v2

This project demonstrates how to integrate [Keycloak](https://www.keycloak.org/) authentication into a Ruby on Rails 8 application, using OAuth2 and role-based access control.

## Features

- 🔐 Login via Keycloak (`/login`)
- ✅ Role-based access: `user` → `/secured`, `admin` → `/admin`
- 🔄 Session-based token storage
- ↪️ Dynamic redirect after login based on user role
- 🧪 Ready to test with Postman or cURL

## Setup

1. Clone the repo:
   ```bash
   git clone https://github.com/your-name/rails8-keycloak-integration.git
   cd rails8-keycloak-integration
   Set up environment variables (see .env.example):
   ```

.ENV

```env

KEYCLOAK_REALM=quickstart
KEYCLOAK_SITE=http://localhost:8080
KEYCLOAK_CLIENT_ID=test-cli
KEYCLOAK_CLIENT_SECRET=your-secret
KEYCLOAK_REDIRECT_URI=http://localhost:3000/auth/callback
Run the Rails server:
```

```bash
bundle install
```

```bash
bin/rails s OR bin/dev
```

Usage

Visit http://localhost:3000

```bash
Click "Login with Keycloak"
```

After login:

```bash
Users with the user role → /secured

Users with the admin role → /admin
```

Testing with cURL

```bash
curl -H "Authorization: Bearer <access_token>" http://localhost:3000/secured
curl -H "Authorization: Bearer <admin_access_token>" http://localhost:3000/admin
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
