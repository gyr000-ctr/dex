package client

import (
	"context"

	"github.com/dexidp/dex/storage"
)

// CreatePushedAuthRequest saves provided pushed auth request into the database.
func (d *Database) CreatePushedAuthRequest(ctx context.Context, request storage.PushedAuthRequest) error {
	_, err := d.client.PushedAuthRequest.Create().
		SetID(request.ID).
		SetClientID(request.ClientID).
		SetParams(request.Params).
		// Save utc time into database because ent doesn't support comparing dates with different timezones
		SetExpiry(request.Expiry.UTC()).
		Save(ctx)
	if err != nil {
		return convertDBError("create pushed auth request: %w", err)
	}
	return nil
}

// GetPushedAuthRequest extracts a pushed auth request from the database by id.
func (d *Database) GetPushedAuthRequest(ctx context.Context, id string) (storage.PushedAuthRequest, error) {
	pushedAuthRequest, err := d.client.PushedAuthRequest.Get(ctx, id)
	if err != nil {
		return storage.PushedAuthRequest{}, convertDBError("get pushed auth request: %w", err)
	}
	return toStoragePushedAuthRequest(pushedAuthRequest), nil
}

// DeletePushedAuthRequest deletes a pushed auth request from the database by id.
func (d *Database) DeletePushedAuthRequest(ctx context.Context, id string) error {
	err := d.client.PushedAuthRequest.DeleteOneID(id).Exec(ctx)
	if err != nil {
		return convertDBError("delete pushed auth request: %w", err)
	}
	return nil
}
