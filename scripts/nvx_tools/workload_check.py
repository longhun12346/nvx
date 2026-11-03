"""Check installed Python versions and the exact runtime dependency closure."""

import importlib.metadata
from pathlib import Path
import sys

from pip._vendor.packaging.requirements import Requirement
from pip._vendor.packaging.utils import canonicalize_name


def check(target: Path, requirements: list[str]) -> dict[str, str]:
    installed = {canonicalize_name(d.metadata["Name"]): d
                 for d in importlib.metadata.distributions(path=[str(target)])}
    pending = [Requirement(text) for text in requirements] + [Requirement("pip")]
    visited = set()
    needed = set()
    while pending:
        requirement = pending.pop()
        name = canonicalize_name(requirement.name)
        distribution = installed.get(name)
        if distribution is None or not requirement.specifier.contains(distribution.version):
            raise ValueError(f"unsatisfied workload requirement: {requirement}")
        needed.add(name)
        for extra in {"", *requirement.extras}:
            if (name, extra) in visited:
                continue
            visited.add((name, extra))
            for text in distribution.requires or []:
                dependency = Requirement(text)
                if dependency.marker is None or dependency.marker.evaluate({"extra": extra}):
                    pending.append(dependency)
    surplus = installed.keys() - needed
    if surplus:
        raise ValueError(f"packages outside the workload dependency closure: {sorted(surplus)}")
    return {name: installed[name].version for name in sorted(needed)}


if __name__ == "__main__":
    import json
    lock = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    versions = check(Path(sys.argv[1]), lock["requirements"])
    expected = {canonicalize_name(p["name"]): p["version"] for p in lock["packages"]}
    if versions != expected:
        raise ValueError("installed Python versions differ from the workload lock")
    print(json.dumps({"pythonPackages": len(versions), "directRequirements": len(lock["requirements"])}))
