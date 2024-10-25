import * as ldap from 'ldapjs';

/**
 * @typedef {Object} LdapConfig
 * @property {string} url - The URL of the LDAP server.
 * @property {string} baseDN - The base DN for LDAP operations.
 */
interface LdapConfig {
    url: string;
    baseDN: string;
}

/**
 * @typedef {Object} DomainInfo
 * @property {string} [username] - The username of the domain user.
 * @property {string} [mail] - The email address of the domain user.
 */
interface DomainInfo {
    username?: string;
    mail?: string;
}

/**
 * Class representing a client for interacting with an LDAP server.
 */
class LdapClient {
    private config: LdapConfig;
    private client: ldap.Client | null;

    /**
     * Creates an instance of the LDAP client.
     * @param {LdapConfig} config - Configuration for the LDAP client.
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
            this.client.on('error', (err: Error) => reject(err));
        });
    }

    /**
     * Authenticates the user.
     * @param {string} username - The username to authenticate.
     * @param {string} password - The user's password.
     * @returns {Promise<boolean>} - A promise that resolves to true if authentication is successful.
     * @throws {Error} - If authentication fails or client is not initialized.
     */
    public async authenticate(username: string, password: string): Promise<boolean> {
        const userDN = `uid=${username},${this.config.baseDN}`;
        return new Promise((resolve, reject) => {
            if (!this.client) {
                return reject(new Error('Client not initialized'));
            }

            this.client.bind(userDN, password, (err) => {
                if (err) return reject(new Error('Authentication failed'));
                resolve(true);
            });
        });
    }

    /**
     * Authenticates the user and retrieves their groups.
     * @param {string} username - The username to authenticate.
     * @param {string} password - The user's password.
     * @returns {Promise<{ isAuthenticated: boolean; groups: string[] }>} - An object indicating if authentication was successful and the user's groups.
     * @throws {Error} - If authentication fails or client is not initialized.
     */
    public async authGroups(username: string, password: string): Promise<{ isAuthenticated: boolean; groups: string[] }> {
        const userDN = `uid=${username},${this.config.baseDN}`;

        return new Promise(async (resolve, reject) => {
            try {
                if (!this.client) {
                    return reject(new Error('Client not initialized'));
                }

                // Perform authentication
                await new Promise<void>((resolveBind, rejectBind) => {
                    this.client!.bind(userDN, password, (err) => {
                        if (err) return rejectBind(new Error('Authentication failed'));
                        resolveBind();
                    });
                });

                // Get the user's groups
                const groups = await this.getUserGroups(username);
                resolve({ isAuthenticated: true, groups });

            } catch (err) {
                reject(err);
            }
        });
    }

    /**
     * Executes a custom LDAP search.
     * @param {string} filter - The LDAP search filter.
     * @param {string[]} attributes - The attributes to retrieve in the search.
     * @returns {Promise<ldap.SearchEntry[]>} - An array of search results.
     * @throws {Error} - If the client is not initialized or search fails.
     */
    public async search(filter: string, attributes: string[]): Promise<ldap.SearchEntry[]> {
        const searchOptions: ldap.SearchOptions = {
            filter,
            scope: 'sub',
            attributes,
        };

        return new Promise((resolve, reject) => {
            if (!this.client) {
                return reject(new Error('Client not initialized'));
            }

            const results: ldap.SearchEntry[] = [];
            this.client.search(this.config.baseDN, searchOptions, (err, res) => {
                if (err) return reject(new Error('LDAP search error'));

                res.on('searchEntry', (entry: ldap.SearchEntry) => {
                    results.push(entry);
                });

                res.on('end', (result) => {
                    if (result && result.status !== 0) {
                        return reject(new Error(`Search failed with status: ${result.status}`));
                    }
                    resolve(results);
                });

                res.on('error', (err) => reject(err));
            });
        });
    }

    /**
     * Searches for the user's groups.
     * @param {string} username - The username to search for groups.
     * @returns {Promise<string[]>} - An array of groups the user belongs to.
     * @throws {Error} - If the client is not initialized or search fails.
     */
    public async getUserGroups(username: string): Promise<string[]> {
        const searchOptions: ldap.SearchOptions = {
            filter: `(uid=${username})`,
            scope: 'sub',
            attributes: ['memberOf']
        };

        return new Promise((resolve, reject) => {
            if (!this.client) {
                return reject(new Error('Client not initialized'));
            }

            const groups: string[] = [];
            this.client.search(this.config.baseDN, searchOptions, (err, res) => {
                if (err) return reject(new Error('Error searching groups'));

                res.on('searchEntry', (entry: ldap.SearchEntry) => {
                    const memberOfAttr = entry.attributes.find(attr => attr.type === 'memberOf');
                    if (memberOfAttr && memberOfAttr.vals) {
                        groups.push(...memberOfAttr.vals);
                    }
                });

                res.on('end', (result) => {
                    if (result && result.status !== 0) {
                        return reject(new Error(`Search failed with status: ${result.status}`));
                    }
                    resolve(groups);
                });

                res.on('error', (err) => reject(err));
            });
        });
    }

    /**
     * Retrieves the user's domain information.
     * @param {string} username - The username to get domain information for.
     * @returns {Promise<DomainInfo>} - An object containing the user's domain information.
     * @throws {Error} - If the client is not initialized or search fails.
     */
    public async getDomainInfo(username: string): Promise<DomainInfo> {
        const searchOptions: ldap.SearchOptions = {
            filter: `(uid=${username})`,
            scope: 'sub',
            attributes: ['sAMAccountName', 'mail']
        };

        return new Promise((resolve, reject) => {
            if (!this.client) {
                return reject(new Error('Client not initialized'));
            }

            const domainInfo: DomainInfo = {};
            this.client.search(this.config.baseDN, searchOptions, (err, res) => {
                if (err) return reject(new Error('Domain search error'));

                res.on('searchEntry', (entry: ldap.SearchEntry) => {
                    const usernameAttr = entry.attributes.find(attr => attr.type === 'sAMAccountName');
                    const mailAttr = entry.attributes.find(attr => attr.type === 'mail');
                    domainInfo.username = usernameAttr ? usernameAttr.vals[0] : undefined;
                    domainInfo.mail = mailAttr ? mailAttr.vals[0] : undefined;
                });

                res.on('end', (result) => {
                    if (result && result.status !== 0) {
                        return reject(new Error(`Search failed with status: ${result.status}`));
                    }
                    resolve(domainInfo);
                });

                res.on('error', (err) => reject(err));
            });
        });
    }

    /**
     * Disconnects from the LDAP server.
     * @returns {Promise<boolean>} - A promise that resolves to true if the disconnection was successful.
     * @throws {Error} - If an error occurs during disconnection.
     */
    public unbind(): Promise<boolean> {
        return new Promise((resolve, reject) => {
            if (this.client) {
                this.client.unbind((err) => {
                    if (err) return reject(new Error('Error during disconnection'));
                    resolve(true);
                });
            } else {
                resolve(false);
            }
        });
    }
}

export default LdapClient;
