"""Safe external-command construction without shell interpolation."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType


@dataclass(frozen=True, slots=True)
class Command:
    """An executable and its literal argument vector."""

    executable: str
    arguments: tuple[str, ...] = ()
    cwd: Path | None = None
    environment: Mapping[str, str] | None = None

    def __post_init__(self) -> None:
        _validate_argument("executable", self.executable)
        if not isinstance(self.arguments, tuple):
            raise TypeError("arguments must be a tuple of strings")
        for index, argument in enumerate(self.arguments):
            _validate_argument(f"arguments[{index}]", argument, allow_empty=True)
        if self.cwd is not None and not isinstance(self.cwd, Path):
            raise TypeError("cwd must be a pathlib.Path or None")
        if self.environment is not None:
            if not isinstance(self.environment, Mapping):
                raise TypeError("environment must be a string mapping or None")
            copied: dict[str, str] = {}
            for key, value in self.environment.items():
                _validate_argument("environment key", key)
                _validate_argument(f"environment[{key}]", value, allow_empty=True)
                if "=" in key:
                    raise ValueError("environment keys cannot contain '='")
                copied[key] = value
            object.__setattr__(
                self,
                "environment",
                MappingProxyType(copied),
            )

    @property
    def argv(self) -> tuple[str, ...]:
        """Return the exact argument vector passed to the process API."""
        return (self.executable, *self.arguments)

    @classmethod
    def from_sequence(
        cls,
        values: Sequence[str],
        *,
        cwd: Path | None = None,
        environment: Mapping[str, str] | None = None,
    ) -> Command:
        """Construct a command from a non-empty argument sequence."""
        if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
            raise TypeError("command values must be a sequence of strings")
        if not values:
            raise ValueError("command values must not be empty")
        return cls(
            executable=values[0],
            arguments=tuple(values[1:]),
            cwd=cwd,
            environment=environment,
        )


def _validate_argument(name: str, value: object, *, allow_empty: bool = False) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{name} must be a string")
    if not allow_empty and not value:
        raise ValueError(f"{name} must not be empty")
    if "\x00" in value:
        raise ValueError(f"{name} must not contain a null byte")


__all__ = ["Command"]
