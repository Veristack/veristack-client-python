"""Client for Veristack."""

from __future__ import absolute_import

from veristack.client import (
    Client, DeviceDetails, FileDetails, LocationDetails, PersonDetails, Event,
    ACTION_TYPES, ACT_CREATE, ACT_READ, ACT_WRITE, ACT_DELETE, ACT_MOVE,
    ACT_COPY, DEVICE_TYPES, DEV_CLOUD, DEV_DESKTOP,
)

__all__ = ('Client', 'DeviceDetails', 'FileDetails', 'LocationDetails',
           'PersonDetails', 'Event', 'ACTION_TYPES', 'ACT_CREATE', 'ACT_READ',
           'ACT_WRITE', 'ACT_DELETE', 'ACT_MOVE', 'ACT_COPY', 'DEVICE_TYPES',
           'DEV_CLOUD', 'DEV_DESKTOP',
           )
