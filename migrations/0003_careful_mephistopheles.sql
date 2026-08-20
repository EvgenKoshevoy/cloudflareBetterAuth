CREATE TABLE `oauth_client_resource` (
	`id` text PRIMARY KEY NOT NULL,
	`client_id` text NOT NULL,
	`resource_id` text NOT NULL,
	`metadata` text,
	`created_at` integer,
	FOREIGN KEY (`client_id`) REFERENCES `oauth_client`(`client_id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`resource_id`) REFERENCES `oauth_resource`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `oauth_client_resource_client_id_idx` ON `oauth_client_resource` (`client_id`);--> statement-breakpoint
CREATE INDEX `oauth_client_resource_resource_id_idx` ON `oauth_client_resource` (`resource_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_client_resource_client_resource_idx` ON `oauth_client_resource` (`client_id`,`resource_id`);--> statement-breakpoint
CREATE TABLE `oauth_resource` (
	`id` text PRIMARY KEY NOT NULL,
	`identifier` text NOT NULL,
	`name` text NOT NULL,
	`access_token_ttl` integer,
	`refresh_token_ttl` integer,
	`signing_algorithm` text,
	`signing_key_id` text,
	`allowed_scopes` text,
	`custom_claims` text,
	`dpop_bound_access_tokens_required` integer,
	`disabled` integer,
	`created_at` integer,
	`updated_at` integer,
	`policy_version` integer,
	`metadata` text
);
--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_resource_identifier_unique` ON `oauth_resource` (`identifier`);