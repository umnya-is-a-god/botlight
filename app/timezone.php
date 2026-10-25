<?php

// TZ from .env; UTC if it is not set
date_default_timezone_set(getenv('TZ') ?: 'UTC');
