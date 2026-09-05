# Teslo | Shop

> An electric-style e-commerce storefront and admin dashboard, inspired by Tesla. Built with Angular.

**Teslo | Shop** is a full-stack practice application with an Angular 19 front-end and a REST API backend. It features a modern storefront for browsing products by category, a product detail page with an image carousel, authentication with role-based access, and a complete admin dashboard for managing products.

## Features

### Store Front

- Product catalog filtered by gender (`/gender/men`, `/gender/women`, `/gender/kids`).
- Product detail pages with an interactive image carousel (Swiper).
- Responsive navigation bar with mobile menu.
- Custom 404 / not-found page.
- Paginated product browsing.

### Authentication

- Login and register pages.
- JWT-based auth with `AuthInterceptor` attaching the token to requests.
- Route guards: `NotAuthenticatedGuard` (redirects logged-in users away from `/auth`) and `IsAdminGuard` (restricts `/admin` to admins).

### Admin Dashboard

- Products list with a management table.
- Create / edit products with validation (reactive forms).
- Role-based access control (only admins can manage products).
- Sidebar layout with navigation.

## Tech Stack

| Layer      | Technology                                             |
| ---------- | ------------------------------------------------------ |
| Framework  | [Angular](https://angular.dev) 19                       |
| Language   | [TypeScript](https://www.typescriptlang.org) ~5.6        |
| Styling    | [Tailwind CSS](https://tailwindcss.com) 3 + [daisyUI](https://daisyui.com) 4 (`night` theme) |
| Carousel   | [Swiper](https://swiperjs.com) 12                       |
| Fonts      | Montserrat Alternates                                   |
| Backend    | REST API at `https://angular-teslo-shop-app-backend.onrender.com/api` |

## Prerequisites

- [Node.js](https://nodejs.org) 18 or later.
- [Angular CLI](https://angular.dev/tools/cli) installed globally (recommended):

```bash
npm install -g @angular/cli
```

## Getting Started

Install the dependencies:

```bash
npm install
```

## Development Server

Run a local development server:

```bash
npm start
# or
ng serve
```

Navigate to `http://localhost:4200/`. The application automatically reloads whenever a source file changes.

## Build

Build the project for production:

```bash
npm run build
```

The build artifacts are stored in the `dist/` directory. Production builds are optimized for performance and speed.

## Running Tests

Execute unit tests with Karma:

```bash
npm test
```

## Environment Configuration

API URLs are managed through environment files under `src/environments/`:

- `environment.ts` — production configuration.
- `environment.development.ts` — development configuration (used with `ng serve`).

The main backend endpoint is defined in `environment.ts`:

```ts
export const environment = {
  baseUrl: 'https://angular-teslo-shop-app-backend.onrender.com/api',
};
```

> **Note:** This repository only contains the front-end. The backend must be running (or reachable at `baseUrl`) for account creation, login, and product data to work.

## Project Structure

```
src/
└── app/
    ├── auth/               # Login, register, auth service, guards, interceptors
    ├── store-front/        # Public pages: home, gender, product detail, 404
    │   └── layouts/        # Storefront layout + navbar
    ├── admin-dashboard/    # Admin pages: products list, product form
    │   └── layouts/        # Admin sidebar layout
    ├── products/           # Product interfaces, service, pipes, shared components
    ├── shared/             # Shared components, interceptors
    ├── utils/              # Utility helpers (form utilities)
    └── app.routes.ts       # Root routing configuration
```

| Path                  | Description                                        |
| --------------------- | -------------------------------------------------- |
| `/`                   | Home page                                          |
| `/gender/:gender`     | Product listing by gender (men / women / kids)     |
| `/product/:idSlug`    | Product detail page                                |
| `/auth/login`         | Login (guarded for non-authenticated users)        |
| `/auth/register`      | Register                                           |
| `/admin/products`     | Products management (admin only)                   |
| `/admin/products/:id` | Create / edit a product (admin only)               |


## Notes

It was created for learning purposes following the [Udemy](https://www.udemy.com).