def present(name, password, **kwargs):
    """
    Ensure role has a password set with SCRAM encryption.
    :param name: name of role
    :param password: SASLprep(password)
    """
    ret = {'name': name, 'changes': {}, 'comment': ''}
    match = __salt__['pg_scram.check'](name, password, **kwargs)
    if match:
        ret['comment'] = 'Password for %s already matches' % name
        ret['result'] = True
        return ret

    ret['changes']['password'] = True

    if __opts__['test']:
        ret['comment'] = 'Password for %s would be updated' % name
        ret['result'] = None
        return ret

    ret['result'] = __salt__['pg_scram.update'](name, password, **kwargs)
    if ret['result']:
        ret['comment'] = 'Password for %s has been updated' % name
    else:
        ret['comment'] = 'Failed to update password for %s' % name
    return ret
