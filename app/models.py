from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


def utcnow() -> datetime:
    return datetime.now(UTC)


class Project(Base):
    __tablename__ = "projects"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    api_keys: Mapped[list["ApiKey"]] = relationship(
        back_populates="project", cascade="all, delete-orphan"
    )
    builds: Mapped[list["Build"]] = relationship(
        back_populates="project", cascade="all, delete-orphan", order_by="Build.id.desc()"
    )

    @property
    def latest_build(self) -> "Build | None":
        return self.builds[0] if self.builds else None


class ApiKey(Base):
    """Per-project ingest key. Only the SHA-256 hash is stored."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    label: Mapped[str] = mapped_column(String(100), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    project: Mapped[Project] = relationship(back_populates="api_keys")


class Build(Base):
    """One pipeline run's scan of one image."""

    __tablename__ = "builds"

    id: Mapped[int] = mapped_column(primary_key=True)
    project_id: Mapped[int] = mapped_column(ForeignKey("projects.id"), index=True)
    commit_sha: Mapped[str] = mapped_column(String(64), default="")
    branch: Mapped[str] = mapped_column(String(255), default="")
    image_ref: Mapped[str] = mapped_column(String(500), default="")
    image_digest: Mapped[str] = mapped_column(String(100), default="")
    pipeline_url: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    # Denormalized counts so the project list never has to scan findings.
    critical: Mapped[int] = mapped_column(Integer, default=0)
    high: Mapped[int] = mapped_column(Integer, default=0)
    medium: Mapped[int] = mapped_column(Integer, default=0)
    low: Mapped[int] = mapped_column(Integer, default=0)
    unknown: Mapped[int] = mapped_column(Integer, default=0)

    project: Mapped[Project] = relationship(back_populates="builds")
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="build", cascade="all, delete-orphan"
    )
    components: Mapped[list["Component"]] = relationship(
        back_populates="build", cascade="all, delete-orphan"
    )

    @property
    def counts(self) -> dict[str, int]:
        return {
            "critical": self.critical,
            "high": self.high,
            "medium": self.medium,
            "low": self.low,
            "unknown": self.unknown,
        }


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(primary_key=True)
    build_id: Mapped[int] = mapped_column(ForeignKey("builds.id"), index=True)
    vuln_id: Mapped[str] = mapped_column(String(100))
    package_name: Mapped[str] = mapped_column(String(255))
    installed_version: Mapped[str] = mapped_column(String(255), default="")
    fixed_version: Mapped[str | None] = mapped_column(String(255))
    severity: Mapped[str] = mapped_column(String(20), index=True)
    title: Mapped[str] = mapped_column(Text, default="")
    target: Mapped[str] = mapped_column(String(500), default="")

    build: Mapped[Build] = relationship(back_populates="findings")


class Component(Base):
    """A package from the image's SBOM."""

    __tablename__ = "components"

    id: Mapped[int] = mapped_column(primary_key=True)
    build_id: Mapped[int] = mapped_column(ForeignKey("builds.id"), index=True)
    name: Mapped[str] = mapped_column(String(255))
    version: Mapped[str] = mapped_column(String(255), default="")
    purl: Mapped[str] = mapped_column(String(1000), default="")
    type: Mapped[str] = mapped_column(String(50), default="")

    build: Mapped[Build] = relationship(back_populates="components")
