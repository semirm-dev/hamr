package hamr

import (
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

/*
	Helpers for different database drivers.
	Postgres, MySql, SqlServer...
*/

func PostgresDb(connString string) (*gorm.DB, error) {
	return gorm.Open(postgres.Open(connString), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
}

func MySqlDb(connString string) (*gorm.DB, error) {
	return gorm.Open(mysql.Open(connString), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
}

func SqlServerDb(connString string) (*gorm.DB, error) {
	return gorm.Open(sqlserver.Open(connString), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Info),
	})
}
