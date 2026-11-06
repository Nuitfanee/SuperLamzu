"""Verified paired FULL/SUPER export; no hardware operations."""
import json
from pathlib import Path

from superlamzu.hexfile import Image

from . import target as T
from .full import build_pair,scope,filenames


def validate_destinations(directory,profile='FULL'):
    directory=Path(directory).resolve()
    paths=[directory/name for name in filenames(profile)]
    protected=[T.WORKSPACE/'firmware',T.WORKSPACE/'backups',T.WORKSPACE/'references']
    for folder in protected:
        if directory==folder.resolve() or folder.resolve() in directory.parents:
            raise ValueError(f'{profile} output must not overwrite firmware, backups or references')
    if any(path.is_dir() or path.with_suffix('.json').is_dir() for path in paths):
        raise ValueError(f'{profile} destination is a directory')
    return paths


def build(directory=None,profile='FULL'):
    paths=validate_destinations(directory or T.WORKSPACE/'build'/'MAYA_X_V2'/profile,profile)
    mouse,receiver=build_pair(profile)
    from .verify import verify
    verification=verify(mouse,receiver)  # Both pass before either is exported.
    manifests=[]
    for role,builder,path in zip(('mouse','receiver'),(mouse,receiver),paths):
        manifest=builder.manifest(profile)
        manifest.update(role=role,scope=scope(profile),verification=verification,output=str(path))
        if role=='mouse':
            manifest.update(extension=builder.extension,advanced=builder.advanced,
                optical=builder.optical,motion=builder.motion,absolute=builder.absolute,
                recipe_compression=builder.recipes)
        else:manifest.update(queue=builder.queue,absolute=builder.absolute)
        builder.write(path)
        manifest_path=path.with_suffix('.json')
        manifest_path.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
        manifests.append(dict(role=role,hex=str(path),manifest=str(manifest_path),changed_bytes=len(builder.changes)))
    report=dict(scope=scope(profile),verification=verification,artifacts=manifests)
    paths[0].parent.joinpath(f'MAYA_{profile}_pair.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return report


def verify_exports(directory=None,profile='FULL'):
    paths=validate_destinations(directory or T.WORKSPACE/'build'/'MAYA_X_V2'/profile,profile)
    pair=build_pair(profile)
    for builder,path in zip(pair,paths):
        actual=Image(path);expected=dict(builder.image.mem);expected.update(builder.changes)
        if actual.mem!=expected or actual.entry!=builder.image.entry:
            raise ValueError(f'{profile} artifact differs from reproducible sparse build: {path}')
    from .verify import verify
    return verify(*pair)
