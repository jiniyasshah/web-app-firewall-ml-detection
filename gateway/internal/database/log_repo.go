package database

import (
	"context"
	"errors"
	"time"
	"web-app-firewall-ml-detection/internal/models"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

type LogFilter struct {
	UserID   string
	DomainID string
	Page     int64
	Limit    int64
}

type PaginatedLogs struct {
	Data       []models.AttackLog `json:"data"` 
	Pagination struct {
		CurrentPage int64 `json:"current_page"`
		TotalPages  int64 `json:"total_pages"`
		TotalItems  int64 `json:"total_items"`
		PerPage     int64 `json:"per_page"`
	} `json:"pagination"`
}

func GetLogs(client *mongo.Client, filter LogFilter) (*PaginatedLogs, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	collection := client.Database(DBName).Collection("logs")
	mongoFilter := bson.M{}

	if filter.DomainID != "" {
		// Verify domain ownership first
		domain, err := GetDomainByID(client, filter.DomainID) // Safe call to domain_repo function
		if err != nil { return nil, err }
		if domain.UserID != filter.UserID { return nil, errors.New("unauthorized") }
		mongoFilter["domain_id"] = filter.DomainID
	} else {
		mongoFilter["user_id"] = filter.UserID
	}

	totalItems, err := collection.CountDocuments(ctx, mongoFilter)
	if err != nil { return nil, err }

	if filter.Page < 1 { filter.Page = 1 }
	if filter.Limit < 1 { filter.Limit = 20 }
	skip := (filter.Page - 1) * filter.Limit
	totalPages := int64(0)
	if filter.Limit > 0 {
		totalPages = (totalItems + filter.Limit - 1) / filter.Limit
	}

	opts := options.Find().
		SetSort(bson.D{{Key: "timestamp", Value: -1}}).
		SetSkip(skip).
		SetLimit(filter.Limit)

	cursor, err := collection.Find(ctx, mongoFilter, opts)
	if err != nil { return nil, err }
	defer cursor.Close(ctx)

	var logs []models.AttackLog
	if err = cursor.All(ctx, &logs); err != nil { return nil, err }
	if logs == nil { logs = []models.AttackLog{} }

	return &PaginatedLogs{
		Data: logs,
		Pagination: struct {
			CurrentPage int64 `json:"current_page"`
			TotalPages  int64 `json:"total_pages"`
			TotalItems  int64 `json:"total_items"`
			PerPage     int64 `json:"per_page"`
		}{
			CurrentPage: filter.Page,
			TotalPages:  totalPages,
			TotalItems:  totalItems,
			PerPage:     filter.Limit,
		},
	}, nil
}