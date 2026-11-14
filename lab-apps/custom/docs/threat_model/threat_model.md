# Summary
---
This is a Data flow and Threat/Safety model report for Custom App 1 - a vulnerable web application designed to educate about API security.
Uses STRIDE framework
# Asset Information
---
- **Name:** Custom App 1
- **Description:** 
- **Internet Facing:** Yes
- **Authentication Type:** PASSWORD
# Threat modeling DFD
---
### Data flow diagram
Placeholder
### Data flow reports
#### External entities
- **Customer**: A person interacting with the service for consuming needs.
- **Supplier**: A person interacting with the service for supplying needs.
- **Support**: 
- **Admin user**: User with high privileges.
#### Processes
- **Authentication Process**: Handles user login and authentication, including login with email token. 
- **Reset password process**: Handle the generation and verification of the OTP. Potential vulnerability related to the OTP code.
- **User profile edit process**: Handle user profile video update and convert. Including profile video deletion action executed by admin user.
- **Email changing process**: Handle the submission of new emails from user to the application. It includes the process of verifying the Email token.
- **Posts handling process**: Manages posts and comments in the forum.
- **Coupon handling process**: Manages discount coupon created by users, including create, validate and applying coupon codes to discount items.
- **Product managing process**: Handles the process of adding new products into the catalog
- **Order tracking process**: Handles the ordering process from creation, update to tracking orders.
- **Mechanic & service management process**: Covering mechanic-related processes including assigning, and tracking service reports.
#### Data stores
- **User database**: Stores all user data, including login credentials and profile information. Security considerations include potential exposure of sensitive data.
- **Workshop database**: Stores all data related to service and workshop, including mechanic informations, product informations and order data.
- **Community database**: Stores community related data including posts, comments, and coupons.
#### Trust Boundaries
- **Internet Boundary**: Separates external actors (User, Admin, Mail Service) from internal API endpoints. Enforces authentication and input validation.
- **Service Authorization Boundary**: Separates incoming requests from microservice business logic. Enforces role-based and object-level access controls (protecting against BOLA/BFLA).
- **Data Persistence Boundary**: Separates backend process execution from database storage layers. Restricts direct data access to authenticated micro-service queries.
# Threat table