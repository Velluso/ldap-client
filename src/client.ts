import * as ldap from 'ldapjs';

/**
 * @typedef {Object} LdapConfig
 * @property {string} url - The URL of the LDAP server (e.g., `ldap://127.0.0.1:1389`).
 * @property {string} userBase - The Domain Components (DC) for user searches (e.g., `dc=example,dc=com`).
 *                                  This is the starting point in the LDAP directory from which user searches will be conducted.
 * @property {string} authorizedGroups - A comma-separated list of groups that are authorized to access the system (e.g., `admins,developers`).
 *                                       Users must belong to one of these groups to be considered authorized.
 */
interface LdapConfig {
    url: string;
    userBase: string;
    authorizedGroups: string;
}

/**
 * Class representing a client for interacting with an LDAP server.
 * This class provides methods to connect to the LDAP server, bind users, retrieve user information, and check authorization.
 */
class LdapClient {
    private config: LdapConfig;
    private client: ldap.Client | null;

    /**
     * Creates an instance of the LDAP client.
     * @param {LdapConfig} config - Configuration for the LDAP client.
     *                               Users can specify the following:
     *                               - `url`: The LDAP server URL.
     *                               - `userBase`: The base Domain Components (DC) for user searches.
     *                               - `authorizedGroups`: A list of groups that are allowed access.
     */
    constructor(config: LdapConfig) {
        this.config = config;
        this.client = null;
    }

    /**
     * Connects to the LDAP server.
     * @returns {Promise<void>} - A promise that resolves when the connection is established.
     * @throws {Error} - If the client is not initialized or connection fails.
     */
    public async connect(): Promise<void> {
        this.client = ldap.createClient({ url: this.config.url });
        return new Promise((resolve, reject) => {
            if (!this.client) {
                return reject(new Error('Client not initialized'));
            }

            this.client.on('connect', () => resolve());
            this.client.on('error', (err: Error) => {
                console.error('Error connecting to LDAP server:', err);
                reject(err);
            });
        });
    }

    /**
     * Binds the user to the LDAP server with provided credentials.
     * @param {string} username - The username to bind, which can be in the format `domain\username` or just `username`.
     * @param {string} password - The user's password.
     * @returns {Promise<void>} - A promise that resolves when the user is successfully bound.
     * @throws {Error} - If authentication fails or client is not initialized.
     */
    public async bind(username: string, password: string): Promise<void> {
        return new Promise((resolve, reject) => {
            if (!this.client) {
                return reject(new Error('Client not initialized'));
            }

            this.client.bind(username, password, (err) => {
                if (err) {
                    console.error('Authentication failed:', err);
                    return reject(err);
                }
                resolve();
            });
        });
    }

    /**
     * Retrieves the groups for a specified user.
     * @param {string} username - The username to search for groups, which can be in the format `domain\username` or just `username`.
     * @returns {Promise<string[]>} - An array of groups the user belongs to.
     * @throws {Error} - If the client is not initialized or search fails.
     */
    public async getUserGroups(username: string): Promise<string[]> {
        return new Promise((resolve, reject) => {
            const userNameWithoutDomain = username.split('\\')[1] || username;
            const searchOptions: ldap.SearchOptions = {
                filter: `(&(objectClass=user)(sAMAccountName=${userNameWithoutDomain}))`,
                scope: 'sub',
                attributes: ['memberOf', 'distinguishedName'],
            };

            const groups: string[] = [];
            if (!this.client) {
                return reject(new Error('Client not initialized'));
            }

            this.client.search(this.config.userBase, searchOptions, (err, res) => {
                if (err) {
                    console.error('Error searching groups:', err);
                    return reject(err);
                }

                res.on('searchEntry', (entry) => {
                    const dnString = entry.objectName ? entry.objectName.toString() : null;
                    if (dnString) {
                        const dnParts = dnString.split(',');
                        for (const part of dnParts) {
                            const [key, value] = part.trim().split('=');
                            if (key === 'OU') {
                                groups.push(value);
                            }
                        }
                    }
                });

                res.on('end', () => resolve(groups));
                res.on('error', (err) => reject(err));
            });
        });
    }

    /**
     * Retrieves the full name of the user.
     * @param {string} username - The username to search for full name, which can be in the format `domain\username` or just `username`.
     * @returns {Promise<string | null>} - The full name of the user or null if not found.
     * @throws {Error} - If the client is not initialized or search fails.
     */
    public async getUserFullName(username: string): Promise<string | null> {
        return new Promise((resolve, reject) => {
            const userNameWithoutDomain = username.split('\\')[1] || username;
            const searchOptions: ldap.SearchOptions = {
                filter: `(&(objectClass=user)(sAMAccountName=${userNameWithoutDomain}))`,
                scope: 'sub',
                attributes: ['distinguishedName', 'cn'],
            };

            let fullName: string | null = null;
            if (!this.client) {
                return reject(new Error('Client not initialized'));
            }

            this.client.search(this.config.userBase, searchOptions, (err, res) => {
                if (err) {
                    console.error('Error searching for full name:', err);
                    return reject(err);
                }

                res.on('searchEntry', (entry) => {
                    const cnAttr = entry.attributes.find(attr => attr.type === 'cn');
                    if (cnAttr && cnAttr.values) {
                        fullName = cnAttr.values[0].toString();
                    }
                });

                res.on('end', () => resolve(fullName));
                res.on('error', (err) => reject(err));
            });
        });
    }

    /**
     * Retrieves the email address of the user.
     * @param {string} username - The username to search for email, which can be in the format `domain\username` or just `username`.
     * @returns {Promise<string | null>} - The email address of the user or null if not found.
     * @throws {Error} - If the client is not initialized or search fails.
     */
    public async getUserEmail(username: string): Promise<string | null> {
        return new Promise((resolve, reject) => {
            const userNameWithoutDomain = username.split('\\')[1] || username;
            const searchOptions: ldap.SearchOptions = {
                filter: `(&(objectClass=user)(sAMAccountName=${userNameWithoutDomain}))`,
                scope: 'sub',
                attributes: ['userPrincipalName'],
            };

            let email: string | null = null;
            if (!this.client) {
                return reject(new Error('Client not initialized'));
            }

            this.client.search(this.config.userBase, searchOptions, (err, res) => {
                if (err) {
                    console.error('Error searching for email:', err);
                    return reject(err);
                }

                res.on('searchEntry', (entry) => {
                    const userPrincipalNameAttr = entry.attributes.find(attr => attr.type === 'userPrincipalName');
                    if (userPrincipalNameAttr && userPrincipalNameAttr.values) {
                        email = userPrincipalNameAttr.values[0].toString();
                    }
                });

                res.on('end', () => resolve(email));
                res.on('error', (err) => reject(err));
            });
        });
    }

    /**
     * Checks if the user is authorized based on their groups.
     * @param {string[]} groups - The groups the user belongs to.
     * @returns {boolean} - True if the user is authorized, false otherwise.
     */
    public isAuthorized(groups: string[]): boolean {
        const authorizedGroups = this.config.authorizedGroups.split(',');
        return groups.some(group => authorizedGroups.includes(group));
    }

    /**
     * Disconnects from the LDAP server.
     * @returns {Promise<boolean>} - A promise that resolves to true if the disconnection was successful.
     * @throws {Error} - If an error occurs during disconnection.
     */
    public async unbind(): Promise<boolean> {
        return new Promise((resolve, reject) => {
            if (this.client) {
                this.client.unbind((err) => {
                    if (err) {
                        console.error('Error during unbind:', err);
                        return reject(err);
                    }
                    resolve(true);
                });
            } else {
                resolve(false);
            }
        });
    }
}

export default LdapClient;
