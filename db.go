package hamr

import (
	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

func SeedCasbinPolicy(db *gorm.DB) {
	runTrans(db, func(tx *gorm.DB) {
		for _, rule := range rules {
			var csr casbinRule
			if err := tx.
				Table("casbin_rule").
				Where(
					"ptype = ? and v0 = ? and v1 = ? and v2 = ?",
					rule.Ptype, rule.v0, rule.v1, rule.v2,
				).Find(&csr).Error; err != nil {
				logrus.Fatal(err)
			}

			if csr.ID == 0 {
				if result := tx.Exec("INSERT INTO casbin_rule(ptype, v0, v1, v2) VALUES (?, ?, ?, ?)",
					rule.Ptype, rule.v0, rule.v1, rule.v2); result.Error != nil {
					tx.Rollback()
					return
				}
			}
		}
	})
}

type casbinRule struct {
	ID                                    uint `gorm:"primarykey"`
	Ptype, v0, v1, v2, v3, v4, v5, v6, v7 string
}

var rules = []*casbinRule{
	{Ptype: "p", v0: "user", v1: "res", v2: "read"},
	{Ptype: "p", v0: "user", v1: "res", v2: "write"},
	{Ptype: "p", v0: "admin", v1: "res", v2: "delete"}, // only admin can delete res
	{Ptype: "g", v0: "admin", v1: "user"},              // assign user policy to admin group
	//{Ptype: "g", v0: "1", v1: "admin"},    // assign user id 1 to admin group
}

func runTrans(db *gorm.DB, trans ...func(tx *gorm.DB)) {
	tx := db.Begin()
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
		}
	}()

	if err := tx.Error; err != nil {
		return
	}

	for _, tr := range trans {
		tr(tx)
	}

	tx.Commit()
}
