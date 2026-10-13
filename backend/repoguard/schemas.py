from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RepositoryInput(StrictModel):
    owner: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,99}$")
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")
    installation_id: int | None = Field(default=None, gt=0)
    fixture_id: str | None = Field(default=None, pattern=r"^(vulnerable|clean)$")

    @model_validator(mode="after")
    def source(self) -> "RepositoryInput":
        if (self.fixture_id is None) == (self.installation_id is None):
            raise ValueError("exactly one of fixture_id or installation_id is required")
        return self


class ScanInput(StrictModel):
    sha: str = Field(pattern=r"^[0-9a-f]{40}$")
    idempotency_key: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:-]+$")
