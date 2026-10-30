"""Private saved selection for explicit starts; callers serialize lifecycle writes."""

from relay_config import RelayError, atomic_json, private_file


_FIELDS = {'target', 'gateway', 'listen_port', 'ssh_destination', 'mode'}
_INVALID = 'Saved relay selection is invalid or unsafe; use an explicit start or stop before automatic recovery.'


def load_resume_mode(config, directory):
    """Return only an owned private selection bound to this exact configuration."""
    try:
        value = private_file(directory / 'intent.json', read=True)
    except FileNotFoundError:
        return None
    except (OSError, RelayError, RecursionError):
        raise RelayError(_INVALID) from None
    if (not isinstance(value, dict) or set(value) != _FIELDS
            or value['mode'] not in ('tls', 'udp')
            or type(value['listen_port']) is not int
            or not isinstance(value['target'], dict)
            or not isinstance(value['gateway'], dict)
            or type(value['target'].get('port')) is not int):
        raise RelayError(_INVALID)
    if (value['target'] != config['target']
            or value['gateway'] != config['gateway']
            or value['listen_port'] != config['listen_port']
            or value['ssh_destination'] != config['ssh_destination']):
        raise RelayError('Saved relay selection does not match the configured target, gateway, port or SSH destination; use an explicit start or stop before automatic recovery.')
    return value['mode']


def save_intent(config, directory, mode):
    """Persist only after a successful explicit start, including ready reuse."""
    if mode not in ('tls', 'udp'):
        raise RelayError('Cannot save an invalid relay backend mode.')
    value = {'target': dict(config['target']), 'gateway': dict(config['gateway']),
             'listen_port': config['listen_port'],
             'ssh_destination': config['ssh_destination'], 'mode': mode}
    try:
        # Atomic replacement never follows an existing symlink or writes through
        # a hard link, and the temporary file is private from its creation.
        atomic_json(directory / 'intent.json', value)
    except OSError:
        raise RelayError('Relay is ready, but saving its backend selection failed. Retry an explicit start or stop; automatic recovery was not confirmed.') from None


def clear_intent(directory):
    """Revoke before stopping, even when no service is running or JSON is unsafe."""
    try:
        # Unlink the directory entry, not its target; never recursively remove
        # unexpected directories or open unsafe metadata to revoke selection.
        (directory / 'intent.json').unlink()
    except FileNotFoundError:
        pass
    except OSError:
        raise RelayError('Cannot clear saved relay selection; the backend was not stopped. Fix intent.json permissions and retry stop.') from None
