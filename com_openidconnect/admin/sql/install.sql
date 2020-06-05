CREATE TABLE IF NOT EXISTS `#__openidconnect_users` (
  `user_id` int NOT NULL,
  `oidc_uuid` varchar(45) NOT NULL,
  UNIQUE KEY `user_id_UNIQUE` (`user_id`),
  UNIQUE KEY `oidc_uuid_UNIQUE` (`oidc_uuid`),
  KEY `user_id_idx` (`user_id`),
  CONSTRAINT `user_id` FOREIGN KEY (`user_id`) REFERENCES `#__users` (`id`) ON DELETE CASCADE ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
