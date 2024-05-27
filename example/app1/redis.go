package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/go-redis/redis"
	"github.com/sirupsen/logrus"

	"github.com/semirm-dev/hamr"
)

// pipeLength defines limit whether to use pipeline or not
const pipeLength = 1

type RedisStorage struct {
	*redis.Client
	*redisConfig
}

type redisConfig struct {
	Host       string
	Port       string
	Password   string
	DB         int
	PipeLength int
}

func newRedisCacheStorage(host, port, password string, cacheDb int) *RedisStorage {
	redisConfig := newRedisConfig()
	redisConfig.Host = host
	redisConfig.Port = port
	redisConfig.Password = password
	redisConfig.DB = cacheDb

	redisConn := &RedisStorage{
		redisConfig: redisConfig,
	}

	if err := redisConn.initialize(); err != nil {
		logrus.Fatal("failed to initialize redis connection: ", err)
	}

	return redisConn
}

func newRedisConfig() *redisConfig {
	return &redisConfig{
		Host:     "",
		Port:     "",
		Password: "",
		DB:       0,
	}
}

func (s *RedisStorage) initialize() error {
	client := redis.NewClient(&redis.Options{
		Addr:     s.redisConfig.Host + ":" + s.redisConfig.Port,
		Password: s.redisConfig.Password, // no password set
		DB:       s.redisConfig.DB,       // use default DB
	})

	if s.redisConfig.PipeLength == 0 {
		s.redisConfig.PipeLength = pipeLength
	}

	_, err := client.Ping().Result()
	if err != nil {
		return err
	}

	s.Client = client

	return nil
}

func (s *RedisStorage) Store(items ...*hamr.Item) error {
	if len(items) > s.redisConfig.PipeLength { // with pipeline
		pipe := s.Client.Pipeline()

		for _, item := range items {
			itemBytes, err := json.Marshal(item.Value)
			if err != nil {
				return err
			}

			pipe.Set(item.Key, string(itemBytes), item.Expiration)
		}

		_, err := pipe.Exec()
		if err != nil {
			return err
		}
	} else { // without pipeline
		var errMsgs []string

		for _, item := range items {
			itemBytes, err := json.Marshal(item.Value)
			if err != nil {
				return err
			}

			if err = s.Client.Set(item.Key, string(itemBytes), item.Expiration).Err(); err != nil {
				errMsgs = append(errMsgs, err.Error())
			}
		}

		if len(errMsgs) > 0 {
			return errors.New(strings.Join(errMsgs, ","))
		}
	}

	return nil
}

func (s *RedisStorage) Load(key string) ([]byte, error) {
	cacheValue, err := s.Client.Get(key).Result()

	switch {
	// key does not exist
	case err == redis.Nil:
		return nil, errors.New(fmt.Sprintf("key %v does not exist", key))
	// some other error
	case err != nil:
		return nil, err
	}

	return []byte(cacheValue), nil
}

func (s *RedisStorage) Delete(keys ...string) error {
	return s.Client.Del(keys...).Err()
}
