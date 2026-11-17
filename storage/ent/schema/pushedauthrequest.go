package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

/* Original SQL table:
create table pushed_auth_request
(
    id         text      not null  primary key,
    client_id  text      not null,
    params     blob      not null,
    expiry     timestamp not null
);
*/

// PushedAuthRequest holds the schema definition for the PushedAuthRequest entity.
type PushedAuthRequest struct {
	ent.Schema
}

// Fields of the PushedAuthRequest.
func (PushedAuthRequest) Fields() []ent.Field {
	return []ent.Field{
		field.Text("id").
			SchemaType(textSchema).
			NotEmpty().
			Unique(),
		field.Text("client_id").
			SchemaType(textSchema).
			NotEmpty(),
		field.JSON("params", map[string][]string{}).
			Optional(),
		field.Time("expiry").
			SchemaType(timeSchema),
	}
}

// Edges of the PushedAuthRequest.
func (PushedAuthRequest) Edges() []ent.Edge {
	return []ent.Edge{}
}
