-- NOTE: this PRAGMA foreign_keys=OFF/ON pair is drizzle-kit's standard
-- SQLite table-rebuild pattern (used whenever a `sqlite` dialect migration
-- needs to recreate a table, e.g. to change its foreign keys/indexes) and was
-- not hand-written. A whole-branch review flagged D1's PRAGMA support as
-- historically partial and asked whether this exact pattern is safe on real
-- (non---local-emulated) D1. No evidence either way was found in this repo's
-- vendored wrangler/drizzle-kit packages (no changelog, no explicit
-- allow/deny list for `foreign_keys`), and this environment has no
-- cloud/deploy access to test against real D1. Left as drizzle-kit generated
-- it rather than hand-edited, to avoid drift from what `db:generate` would
-- produce next time. If this migration ever fails against a real remote D1
-- instance, that is the first thing to suspect.
PRAGMA foreign_keys=OFF;--> statement-breakpoint
CREATE TABLE `__new_oauth_client_resource` (
	`id` text PRIMARY KEY NOT NULL,
	`client_id` text NOT NULL,
	`resource_id` text NOT NULL,
	`metadata` text,
	`created_at` integer,
	FOREIGN KEY (`client_id`) REFERENCES `oauth_client`(`client_id`) ON UPDATE no action ON DELETE cascade,
	FOREIGN KEY (`resource_id`) REFERENCES `oauth_resource`(`identifier`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
INSERT INTO `__new_oauth_client_resource`("id", "client_id", "resource_id", "metadata", "created_at") SELECT "id", "client_id", "resource_id", "metadata", "created_at" FROM `oauth_client_resource`;--> statement-breakpoint
DROP TABLE `oauth_client_resource`;--> statement-breakpoint
ALTER TABLE `__new_oauth_client_resource` RENAME TO `oauth_client_resource`;--> statement-breakpoint
PRAGMA foreign_keys=ON;--> statement-breakpoint
CREATE INDEX `oauth_client_resource_client_id_idx` ON `oauth_client_resource` (`client_id`);--> statement-breakpoint
CREATE INDEX `oauth_client_resource_resource_id_idx` ON `oauth_client_resource` (`resource_id`);--> statement-breakpoint
CREATE UNIQUE INDEX `oauth_client_resource_client_resource_idx` ON `oauth_client_resource` (`client_id`,`resource_id`);