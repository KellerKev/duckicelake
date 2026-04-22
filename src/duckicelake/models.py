"""Pydantic request/response models for the Iceberg REST API subset we serve.

We use dict[str, Any] for TableMetadata because constructing a full Pydantic
schema for every Iceberg v3 field would balloon the prototype. FastAPI will
serialize the returned dict as JSON.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ConfigResponse(BaseModel):
    defaults: dict[str, str] = Field(default_factory=dict)
    overrides: dict[str, str] = Field(default_factory=dict)
    endpoints: list[str] = Field(default_factory=list)


class CreateNamespaceRequest(BaseModel):
    namespace: list[str]
    properties: dict[str, str] = Field(default_factory=dict)


class CreateNamespaceResponse(BaseModel):
    namespace: list[str]
    properties: dict[str, str] = Field(default_factory=dict)


class GetNamespaceResponse(BaseModel):
    namespace: list[str]
    properties: dict[str, str] = Field(default_factory=dict)


class ListNamespacesResponse(BaseModel):
    namespaces: list[list[str]]


class TableIdentifier(BaseModel):
    namespace: list[str]
    name: str


class ListTablesResponse(BaseModel):
    identifiers: list[TableIdentifier]


class CreateTableRequest(BaseModel):
    name: str
    schema_: dict[str, Any] = Field(alias="schema")
    location: str | None = None
    partition_spec: dict[str, Any] | None = Field(default=None, alias="partition-spec")
    write_order: dict[str, Any] | None = Field(default=None, alias="write-order")
    stage_create: bool = Field(default=False, alias="stage-create")
    properties: dict[str, str] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


class LoadTableResponse(BaseModel):
    metadata_location: str | None = Field(default=None, alias="metadata-location")
    metadata: dict[str, Any]
    config: dict[str, str] = Field(default_factory=dict)

    model_config = {"populate_by_name": True}


class RenameTableRequest(BaseModel):
    source: TableIdentifier
    destination: TableIdentifier


class CommitTableRequest(BaseModel):
    identifier: TableIdentifier | None = None
    requirements: list[dict[str, Any]] = Field(default_factory=list)
    updates: list[dict[str, Any]] = Field(default_factory=list)


class ErrorModel(BaseModel):
    message: str
    type: str
    code: int


class IcebergErrorResponse(BaseModel):
    error: ErrorModel
