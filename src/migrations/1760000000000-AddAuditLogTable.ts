import { MigrationInterface, QueryRunner } from 'typeorm';

export class AddAuditLogTable1760000000000 implements MigrationInterface {
  name = 'AddAuditLogTable1760000000000';

  public async up(queryRunner: QueryRunner): Promise<void> {
    // Create audit_log table
    await queryRunner.query(`
      CREATE TABLE IF NOT EXISTS \`audit_log\` (
        \`id\` int NOT NULL AUTO_INCREMENT,
        \`eventType\` varchar(50) NOT NULL,
        \`severity\` varchar(20) NOT NULL DEFAULT 'low',
        \`description\` text NOT NULL,
        \`metadata\` json NULL,
        \`ipAddress\` varchar(45) NULL,
        \`userAgent\` varchar(500) NULL,
        \`httpMethod\` varchar(10) NULL,
        \`endpoint\` varchar(500) NULL,
        \`responseStatus\` int NULL,
        \`userId\` int NULL,
        \`clientId\` int NULL,
        \`resourceId\` int NULL,
        \`resourceType\` varchar(100) NULL,
        \`createdAt\` datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
        INDEX \`IDX_audit_log_user_created\` (\`userId\`, \`createdAt\`),
        INDEX \`IDX_audit_log_client_created\` (\`clientId\`, \`createdAt\`),
        INDEX \`IDX_audit_log_event_created\` (\`eventType\`, \`createdAt\`),
        INDEX \`IDX_audit_log_severity_created\` (\`severity\`, \`createdAt\`),
        INDEX \`IDX_audit_log_ip\` (\`ipAddress\`),
        PRIMARY KEY (\`id\`)
      ) ENGINE=InnoDB
    `);

    // Add foreign key constraints
    await queryRunner.query(`
      ALTER TABLE \`audit_log\`
      ADD CONSTRAINT \`FK_audit_log_user\`
      FOREIGN KEY (\`userId\`) REFERENCES \`user\`(\`id\`) ON DELETE SET NULL ON UPDATE NO ACTION
    `);

    await queryRunner.query(`
      ALTER TABLE \`audit_log\`
      ADD CONSTRAINT \`FK_audit_log_client\`
      FOREIGN KEY (\`clientId\`) REFERENCES \`client\`(\`id\`) ON DELETE SET NULL ON UPDATE NO ACTION
    `);
  }

  public async down(queryRunner: QueryRunner): Promise<void> {
    // Drop foreign key constraints
    await queryRunner.query(
      `ALTER TABLE \`audit_log\` DROP FOREIGN KEY \`FK_audit_log_client\``,
    );
    await queryRunner.query(
      `ALTER TABLE \`audit_log\` DROP FOREIGN KEY \`FK_audit_log_user\``,
    );

    // Drop table
    await queryRunner.query(`DROP TABLE IF EXISTS \`audit_log\``);
  }
}
