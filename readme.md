## Configuration

Define the environment variables to configure the LDAP client:

- `url`: LDAP server URL, e.g., `ldap://127.0.0.1:1389`
- `userBase`: Base for user searches, e.g., `dc=example,dc=com`
- `authorizedGroups`: Comma-separated list of authorized groups

Example configuration:

    const config = {
        url: process.env.LDAP_URL,
        userBase: process.env.LDAP_USER_BASE,
        authorizedGroups: process.env.LDAP_AUTHORIZED_GROUPS
    };

## Usage

### Connecting to the LDAP Server

Import the LDAP client and create an instance of the `LdapClient` class with the configured settings.

    const LdapClient = require('ldap-client-connector');
    const client = new LdapClient(config);
    await client.connect();

### User Authentication

Use the `bind` method to authenticate a user by providing their username and password.

    async function authenticateUser(username, password) {
        try {
            await client.bind(username, password);
            console.log('User successfully authenticated!');
        } catch (error) {
            console.error('Authentication failed:', error);
        }
    }

### Retrieving User Information

After successful authentication, retrieve user information such as groups and email.

    const groups = await client.getUserGroups(username);
    const email = await client.getUserEmail(username);
    console.log('User Groups:', groups);
    console.log('User Email:', email);

### Authorization Check

Verify if the user is part of any authorized groups:

    if (client.isAuthorized(groups)) {
        console.log('User is authorized.');
    } else {
        console.log('User is not authorized.');
    }

### Disconnecting

When done, disconnect from the LDAP server.

    await client.unbind();

## Complete Documentation

For a comprehensive list of methods and configuration options, refer to the `LdapClient` documentation, to see it start a live server from the index.html inside the docs/ folder.
