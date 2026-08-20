import { sqliteTable } from 'drizzle-orm/sqlite-core';
import * as t from 'drizzle-orm/sqlite-core';

export const user = sqliteTable(
    'user',
    {
        id: t.text('id').primaryKey(),
        name: t.text('name').notNull(),
        email: t.text('email').notNull(),
        emailVerified: t.integer('email_verified', { mode: 'boolean' }).notNull(),
        image: t.text('image'),
        role: t.text('role'),
        banned: t.integer('banned', { mode: 'boolean' }),
        banReason: t.text('ban_reason'),
        banExpires: t.integer('ban_expires', { mode: 'timestamp' }),
        createdAt: t.integer('created_at', { mode: 'timestamp' }).notNull(),
        updatedAt: t.integer('updated_at', { mode: 'timestamp' }).notNull(),
    },
    (table) => [t.uniqueIndex('user_email_idx').on(table.email)],
);

export const session = sqliteTable(
    'session',
    {
        id: t.text('id').primaryKey(),
        userId: t
            .text('user_id')
            .notNull()
            .references(() => user.id, { onDelete: 'cascade' }),
        token: t.text('token').notNull(),
        expiresAt: t.integer('expires_at', { mode: 'timestamp' }).notNull(),
        ipAddress: t.text('ip_address'),
        userAgent: t.text('user_agent'),
        impersonatedBy: t.text('impersonated_by'),
        createdAt: t.integer('created_at', { mode: 'timestamp' }).notNull(),
        updatedAt: t.integer('updated_at', { mode: 'timestamp' }).notNull(),
    },
    (table) => [t.uniqueIndex('session_token_idx').on(table.token), t.index('session_user_id_idx').on(table.userId)],
);

export const account = sqliteTable(
    'account',
    {
        id: t.text('id').primaryKey(),
        userId: t
            .text('user_id')
            .notNull()
            .references(() => user.id, { onDelete: 'cascade' }),
        issuer: t.text('issuer').notNull(),
        accountId: t.text('account_id').notNull(),
        providerId: t.text('provider_id').notNull(),
        accessToken: t.text('access_token'),
        refreshToken: t.text('refresh_token'),
        accessTokenExpiresAt: t.integer('access_token_expires_at', { mode: 'timestamp' }),
        refreshTokenExpiresAt: t.integer('refresh_token_expires_at', { mode: 'timestamp' }),
        scope: t.text('scope'),
        idToken: t.text('id_token'),
        password: t.text('password'),
        createdAt: t.integer('created_at', { mode: 'timestamp' }).notNull(),
        updatedAt: t.integer('updated_at', { mode: 'timestamp' }).notNull(),
    },
    (table) => [t.index('account_user_id_idx').on(table.userId), t.uniqueIndex('account_issuer_account_id_idx').on(table.issuer, table.accountId)],
);

export const verification = sqliteTable(
    'verification',
    {
        id: t.text('id').primaryKey(),
        identifier: t.text('identifier').notNull(),
        value: t.text('value').notNull(),
        expiresAt: t.integer('expires_at', { mode: 'timestamp' }).notNull(),
        createdAt: t.integer('created_at', { mode: 'timestamp' }),
        updatedAt: t.integer('updated_at', { mode: 'timestamp' }),
    },
    (table) => [t.index('verification_identifier_idx').on(table.identifier)],
);

export const oauthClient = sqliteTable(
    'oauth_client',
    {
        id: t.text('id').primaryKey(),
        clientId: t.text('client_id').notNull().unique(),
        clientSecret: t.text('client_secret'),
        disabled: t.integer('disabled', { mode: 'boolean' }),
        skipConsent: t.integer('skip_consent', { mode: 'boolean' }),
        enableEndSession: t.integer('enable_end_session', { mode: 'boolean' }),
        subjectType: t.text('subject_type'),
        scopes: t.text('scopes', { mode: 'json' }).$type<string[]>(),
        clientCredentialsScopes: t.text('client_credentials_scopes', { mode: 'json' }).$type<string[]>(),
        userId: t.text('user_id').references(() => user.id, { onDelete: 'cascade' }),
        referenceId: t.text('reference_id'),
        createdAt: t.integer('created_at', { mode: 'timestamp' }),
        updatedAt: t.integer('updated_at', { mode: 'timestamp' }),
        name: t.text('name'),
        uri: t.text('uri'),
        icon: t.text('icon'),
        contacts: t.text('contacts', { mode: 'json' }).$type<string[]>(),
        tos: t.text('tos'),
        policy: t.text('policy'),
        softwareId: t.text('software_id'),
        softwareVersion: t.text('software_version'),
        softwareStatement: t.text('software_statement'),
        redirectUris: t.text('redirect_uris', { mode: 'json' }).$type<string[]>().notNull(),
        postLogoutRedirectUris: t.text('post_logout_redirect_uris', { mode: 'json' }).$type<string[]>(),
        backchannelLogoutUri: t.text('backchannel_logout_uri'),
        backchannelLogoutSessionRequired: t.integer('backchannel_logout_session_required', { mode: 'boolean' }),
        tokenEndpointAuthMethod: t.text('token_endpoint_auth_method'),
        applicationType: t.text('application_type'),
        jwks: t.text('jwks'),
        jwksUri: t.text('jwks_uri'),
        grantTypes: t.text('grant_types', { mode: 'json' }).$type<string[]>(),
        responseTypes: t.text('response_types', { mode: 'json' }).$type<string[]>(),
        clientDiscoveryId: t.text('client_discovery_id'),
        requirePKCE: t.integer('require_pkce', { mode: 'boolean' }),
        dpopBoundAccessTokens: t.integer('dpop_bound_access_tokens', { mode: 'boolean' }),
        metadata: t.text('metadata', { mode: 'json' }),
    },
    (table) => [t.index('oauth_client_user_id_idx').on(table.userId)],
);

export const oauthRefreshToken = sqliteTable(
    'oauth_refresh_token',
    {
        id: t.text('id').primaryKey(),
        token: t.text('token').notNull().unique(),
        clientId: t
            .text('client_id')
            .notNull()
            .references(() => oauthClient.clientId, { onDelete: 'cascade' }),
        sessionId: t.text('session_id').references(() => session.id, { onDelete: 'set null' }),
        userId: t
            .text('user_id')
            .notNull()
            .references(() => user.id, { onDelete: 'cascade' }),
        referenceId: t.text('reference_id'),
        authorizationCodeId: t.text('authorization_code_id'),
        resources: t.text('resources', { mode: 'json' }).$type<string[]>(),
        requestedUserInfoClaims: t.text('requested_user_info_claims', { mode: 'json' }).$type<string[]>(),
        scopes: t.text('scopes', { mode: 'json' }).$type<string[]>().notNull(),
        revoked: t.integer('revoked', { mode: 'timestamp_ms' }),
        rotatedAt: t.integer('rotated_at', { mode: 'timestamp_ms' }),
        rotationReplayResponse: t.text('rotation_replay_response'),
        rotationReplayExpiresAt: t.integer('rotation_replay_expires_at', { mode: 'timestamp_ms' }),
        authTime: t.integer('auth_time', { mode: 'timestamp_ms' }),
        createdAt: t.integer('created_at', { mode: 'timestamp_ms' }).notNull(),
        expiresAt: t.integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
        confirmation: t.text('confirmation', { mode: 'json' }),
    },
    (table) => [
        t.index('oauth_refresh_token_client_id_idx').on(table.clientId),
        t.index('oauth_refresh_token_session_id_idx').on(table.sessionId),
        t.index('oauth_refresh_token_user_id_idx').on(table.userId),
        t.index('oauth_refresh_token_authorization_code_id_idx').on(table.authorizationCodeId),
    ],
);

export const oauthAccessToken = sqliteTable(
    'oauth_access_token',
    {
        id: t.text('id').primaryKey(),
        token: t.text('token').notNull().unique(),
        clientId: t
            .text('client_id')
            .notNull()
            .references(() => oauthClient.clientId, { onDelete: 'cascade' }),
        sessionId: t.text('session_id').references(() => session.id, { onDelete: 'set null' }),
        refreshId: t.text('refresh_id').references(() => oauthRefreshToken.id, { onDelete: 'cascade' }),
        userId: t.text('user_id').references(() => user.id, { onDelete: 'cascade' }),
        referenceId: t.text('reference_id'),
        authorizationCodeId: t.text('authorization_code_id'),
        resources: t.text('resources', { mode: 'json' }).$type<string[]>(),
        requestedUserInfoClaims: t.text('requested_user_info_claims', { mode: 'json' }).$type<string[]>(),
        scopes: t.text('scopes', { mode: 'json' }).$type<string[]>().notNull(),
        createdAt: t.integer('created_at', { mode: 'timestamp_ms' }).notNull(),
        expiresAt: t.integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
        confirmation: t.text('confirmation', { mode: 'json' }),
        revoked: t.integer('revoked', { mode: 'timestamp_ms' }),
    },
    (table) => [
        t.index('oauth_access_token_client_id_idx').on(table.clientId),
        t.index('oauth_access_token_session_id_idx').on(table.sessionId),
        t.index('oauth_access_token_user_id_idx').on(table.userId),
        t.index('oauth_access_token_refresh_id_idx').on(table.refreshId),
        t.index('oauth_access_token_authorization_code_id_idx').on(table.authorizationCodeId),
    ],
);

export const oauthConsent = sqliteTable(
    'oauth_consent',
    {
        id: t.text('id').primaryKey(),
        userId: t.text('user_id').references(() => user.id, { onDelete: 'cascade' }),
        clientId: t
            .text('client_id')
            .notNull()
            .references(() => oauthClient.clientId, { onDelete: 'cascade' }),
        referenceId: t.text('reference_id'),
        resources: t.text('resources', { mode: 'json' }).$type<string[]>(),
        scopes: t.text('scopes', { mode: 'json' }).$type<string[]>().notNull(),
        requestedUserInfoClaims: t.text('requested_user_info_claims', { mode: 'json' }).$type<string[]>(),
        createdAt: t.integer('created_at', { mode: 'timestamp_ms' }).notNull(),
        updatedAt: t.integer('updated_at', { mode: 'timestamp_ms' }).notNull(),
    },
    (table) => [t.index('oauth_consent_client_id_idx').on(table.clientId), t.index('oauth_consent_user_id_idx').on(table.userId)],
);

export const oauthClientAssertion = sqliteTable('oauth_client_assertion', {
    id: t.text('id').primaryKey(),
    expiresAt: t.integer('expires_at', { mode: 'timestamp_ms' }).notNull(),
});

export const oauthResource = sqliteTable('oauth_resource', {
    id: t.text('id').primaryKey(),
    identifier: t.text('identifier').notNull().unique(),
    name: t.text('name').notNull(),
    accessTokenTtl: t.integer('access_token_ttl'),
    refreshTokenTtl: t.integer('refresh_token_ttl'),
    signingAlgorithm: t.text('signing_algorithm'),
    signingKeyId: t.text('signing_key_id'),
    allowedScopes: t.text('allowed_scopes', { mode: 'json' }).$type<string[]>(),
    customClaims: t.text('custom_claims', { mode: 'json' }),
    dpopBoundAccessTokensRequired: t.integer('dpop_bound_access_tokens_required', { mode: 'boolean' }),
    disabled: t.integer('disabled', { mode: 'boolean' }),
    createdAt: t.integer('created_at', { mode: 'timestamp' }),
    updatedAt: t.integer('updated_at', { mode: 'timestamp' }),
    policyVersion: t.integer('policy_version'),
    metadata: t.text('metadata', { mode: 'json' }),
});

// Signing keys for the `jwt()` plugin (used to sign OAuth access tokens /
// ID tokens and to serve /api/auth/jwks). Not part of the oauth-provider
// plugin's own schema - this is better-auth core's jwt plugin table.
export const jwks = sqliteTable('jwks', {
    id: t.text('id').primaryKey(),
    publicKey: t.text('public_key').notNull(),
    privateKey: t.text('private_key').notNull(),
    createdAt: t.integer('created_at', { mode: 'timestamp' }).notNull(),
    expiresAt: t.integer('expires_at', { mode: 'timestamp' }),
    alg: t.text('alg'),
    crv: t.text('crv'),
});

export const oauthClientResource = sqliteTable(
    'oauth_client_resource',
    {
        id: t.text('id').primaryKey(),
        clientId: t
            .text('client_id')
            .notNull()
            .references(() => oauthClient.clientId, { onDelete: 'cascade' }),
        resourceId: t
            .text('resource_id')
            .notNull()
            // References the resource's `identifier` (e.g. "urn:service:serviceb"),
            // not its internal `id` - the plugin's own canonical schema
            // (@better-auth/oauth-provider) declares this FK against
            // oauthResource.identifier and inserts the identifier string
            // directly as resourceId when linking resources.
            .references(() => oauthResource.identifier, { onDelete: 'cascade' }),
        metadata: t.text('metadata', { mode: 'json' }),
        createdAt: t.integer('created_at', { mode: 'timestamp' }),
    },
    (table) => [
        t.index('oauth_client_resource_client_id_idx').on(table.clientId),
        t.index('oauth_client_resource_resource_id_idx').on(table.resourceId),
        t.uniqueIndex('oauth_client_resource_client_resource_idx').on(table.clientId, table.resourceId),
    ],
);
