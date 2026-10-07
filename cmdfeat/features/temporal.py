"""Calendar/clock features derived from the event timestamp (section 20).

Only the *static* part lives here -- hour, weekday, business hours and cyclical
encodings.  Anything that needs the user's history (deviation from their usual
hour, commands in the previous five minutes) lives in
:mod:`cmdfeat.features.behavioral`, which sees events strictly in order.
"""

from __future__ import annotations

import math
from typing import Dict

from ..context import CommandContext
from ..schema import F, KIND_CONTEXT

BUSINESS_START, BUSINESS_END = 8, 18
NIGHT_START, NIGHT_END = 22, 6

FEATURES = [
    F("timestamp_available", "bool", "temporal", KIND_CONTEXT, "The event carried a parsable timestamp."),
    F("epoch_timestamp", "float", "temporal", KIND_CONTEXT, "Unix timestamp in seconds, -1.0 when unavailable.", -1.0),
    F("hour", "int", "temporal", KIND_CONTEXT, "Hour of day in the timestamp's own offset, -1 when unavailable.", -1),
    F("minute", "int", "temporal", KIND_CONTEXT, "Minute of hour, -1 when unavailable.", -1),
    F("day_of_week", "int", "temporal", KIND_CONTEXT, "0=Monday .. 6=Sunday, -1 when unavailable.", -1),
    F("day_of_month", "int", "temporal", KIND_CONTEXT, "Day of month, -1 when unavailable.", -1),
    F("month", "int", "temporal", KIND_CONTEXT, "Month number, -1 when unavailable.", -1),
    F("iso_week", "int", "temporal", KIND_CONTEXT, "ISO week number, -1 when unavailable.", -1),
    F("is_weekend", "bool", "temporal", KIND_CONTEXT, "Saturday or Sunday."),
    F("is_business_hours", "bool", "temporal", KIND_CONTEXT, "Weekday between 08:00 and 18:00."),
    F("is_night", "bool", "temporal", KIND_CONTEXT, "Between 22:00 and 06:00."),
    F("is_off_hours", "bool", "temporal", KIND_CONTEXT, "Outside business hours or at the weekend."),
    F("hour_sin", "float", "temporal", KIND_CONTEXT, "sin(2*pi*hour/24); cyclical encoding for distance-based models.", 0.0),
    F("hour_cos", "float", "temporal", KIND_CONTEXT, "cos(2*pi*hour/24).", 0.0),
    F("day_of_week_sin", "float", "temporal", KIND_CONTEXT, "sin(2*pi*dow/7).", 0.0),
    F("day_of_week_cos", "float", "temporal", KIND_CONTEXT, "cos(2*pi*dow/7).", 0.0),
    F("utc_offset_minutes", "int", "temporal", KIND_CONTEXT, "Timezone offset of the event, 0 when unknown."),
]


def extract(ctx: CommandContext) -> Dict[str, object]:
    """Compute calendar/clock features for one event."""
    timestamp = ctx.event.timestamp
    if timestamp is None:
        return {spec.name: spec.default for spec in FEATURES}

    hour, minute = timestamp.hour, timestamp.minute
    dow = timestamp.weekday()
    weekend = dow >= 5
    business = (not weekend) and BUSINESS_START <= hour < BUSINESS_END
    night = hour >= NIGHT_START or hour < NIGHT_END
    offset = timestamp.utcoffset()
    return {
        "timestamp_available": 1,
        "epoch_timestamp": round(timestamp.timestamp(), 3),
        "hour": hour,
        "minute": minute,
        "day_of_week": dow,
        "day_of_month": timestamp.day,
        "month": timestamp.month,
        "iso_week": timestamp.isocalendar()[1],
        "is_weekend": int(weekend),
        "is_business_hours": int(business),
        "is_night": int(night),
        "is_off_hours": int(not business),
        "hour_sin": round(math.sin(2 * math.pi * hour / 24), 4),
        "hour_cos": round(math.cos(2 * math.pi * hour / 24), 4),
        "day_of_week_sin": round(math.sin(2 * math.pi * dow / 7), 4),
        "day_of_week_cos": round(math.cos(2 * math.pi * dow / 7), 4),
        "utc_offset_minutes": int(offset.total_seconds() // 60) if offset else 0,
    }
