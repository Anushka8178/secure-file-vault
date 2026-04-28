/**
 * Role hierarchy — higher number = more privilege
 * SuperAdmin > Admin > User > ReadOnly
 */
const ROLE_HIERARCHY = {
  ReadOnly: 1,
  User: 2,
  Admin: 3,
  SuperAdmin: 4,
};

const ROLES = Object.keys(ROLE_HIERARCHY);

module.exports = { ROLE_HIERARCHY, ROLES };
