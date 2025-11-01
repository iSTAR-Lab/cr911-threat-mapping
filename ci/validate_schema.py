#!/usr/bin/env python3
import json,sys
from jsonschema import validate,ValidationError
schema=json.load(open('schema/mapping.schema.json'))
data=json.load(open('mapping.json'))
try:
    validate(instance=data,schema=schema)
    print('OK')
except ValidationError as e:
    print('SCHEMA ERROR',e); sys.exit(1)
