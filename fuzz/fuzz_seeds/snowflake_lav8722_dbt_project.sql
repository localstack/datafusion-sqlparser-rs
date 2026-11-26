BEGIN
CREATE DBT PROJECT entitlement_probe FROM '@source' AUTO_COMPILE=FALSE;
ALTER DBT PROJECT entitlement_probe SET COMMENT='probe';
EXECUTE DBT PROJECT entitlement_probe ARGS='run';
END;
