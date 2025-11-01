import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddStatisticsTables1761648568052 implements MigrationInterface {
  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create token_statistics table
    await queryRunner.query(`
            CREATE TABLE \`token_statistics\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`userId\` int NOT NULL,
                \`clientId\` int NULL,
                \`eventType\` enum('issued','revoked','expired') NOT NULL,
                \`eventDate\` date NOT NULL,
                \`count\` int NOT NULL DEFAULT 1,
                \`revokedReason\` varchar(500) NULL,
                \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                PRIMARY KEY (\`id\`)
            ) ENGINE=InnoDB
        `);

    // Create indexes for token_statistics
    await queryRunner.query(`
            CREATE INDEX \`IDX_token_statistics_user_client_event_date\` ON \`token_statistics\` (\`userId\`, \`clientId\`, \`eventType\`, \`eventDate\`)
        `);
    await queryRunner.query(`
            CREATE INDEX \`IDX_token_statistics_event_date\` ON \`token_statistics\` (\`eventDate\`)
        `);
    await queryRunner.query(`
            CREATE INDEX \`IDX_token_statistics_user_id\` ON \`token_statistics\` (\`userId\`)
        `);
    await queryRunner.query(`
            CREATE INDEX \`IDX_token_statistics_client_id\` ON \`token_statistics\` (\`clientId\`)
        `);

    // Create scope_statistics table
    await queryRunner.query(`
            CREATE TABLE \`scope_statistics\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`userId\` int NOT NULL,
                \`scope\` varchar(100) NOT NULL,
                \`eventType\` enum('granted','revoked') NOT NULL,
                \`eventDate\` date NOT NULL,
                \`count\` int NOT NULL DEFAULT 1,
                \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                PRIMARY KEY (\`id\`)
            ) ENGINE=InnoDB
        `);

    // Create indexes for scope_statistics
    await queryRunner.query(`
            CREATE INDEX \`IDX_scope_statistics_user_scope_event_date\` ON \`scope_statistics\` (\`userId\`, \`scope\`, \`eventType\`, \`eventDate\`)
        `);
    await queryRunner.query(`
            CREATE INDEX \`IDX_scope_statistics_event_date\` ON \`scope_statistics\` (\`eventDate\`)
        `);
    await queryRunner.query(`
            CREATE INDEX \`IDX_scope_statistics_user_id\` ON \`scope_statistics\` (\`userId\`)
        `);

    // Create client_statistics table
    await queryRunner.query(`
            CREATE TABLE \`client_statistics\` (
                \`id\` int NOT NULL AUTO_INCREMENT,
                \`userId\` int NOT NULL,
                \`clientId\` int NOT NULL,
                \`clientName\` varchar(255) NOT NULL,
                \`eventDate\` date NOT NULL,
                \`tokensIssued\` int NOT NULL DEFAULT 0,
                \`tokensActive\` int NOT NULL DEFAULT 0,
                \`tokensExpired\` int NOT NULL DEFAULT 0,
                \`tokensRevoked\` int NOT NULL DEFAULT 0,
                \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
                PRIMARY KEY (\`id\`)
            ) ENGINE=InnoDB
        `);

    // Create indexes for client_statistics
    await queryRunner.query(`
            CREATE INDEX \`IDX_client_statistics_user_client_date\` ON \`client_statistics\` (\`userId\`, \`clientId\`, \`eventDate\`)
        `);
    await queryRunner.query(`
            CREATE INDEX \`IDX_client_statistics_event_date\` ON \`client_statistics\` (\`eventDate\`)
        `);
    await queryRunner.query(`
            CREATE INDEX \`IDX_client_statistics_user_id\` ON \`client_statistics\` (\`userId\`)
        `);
    await queryRunner.query(`
            CREATE INDEX \`IDX_client_statistics_client_id\` ON \`client_statistics\` (\`clientId\`)
        `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop tables in reverse order
    await queryRunner.query(`DROP TABLE \`client_statistics\``);
    await queryRunner.query(`DROP TABLE \`scope_statistics\``);
    await queryRunner.query(`DROP TABLE \`token_statistics\``);
  }
}
