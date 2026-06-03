from dmsa_reaper.models import ContainerObject, Environment, MapState, Right, SchemaCache, TargetObject, DmsaObject
from dmsa_reaper.paths.classifier import classify_paths


def test_postpatch_mutual_pair_classifier():
    state = MapState(
        environment=Environment(dmsa_capable=True),
        schema_cache=SchemaCache(),
        containers=[
            ContainerObject(
                dn="OU=Apps,DC=corp,DC=local",
                rights=[Right(principal_sid="S-1-5-21-X-1000", right="CreateChild:dMSA", object_dn="OU=Apps,DC=corp,DC=local")],
            )
        ],
        targets=[
            TargetObject(
                dn="CN=svc,CN=Users,DC=corp,DC=local",
                writable_attrs=["msDS-SupersededManagedAccountLink", "msDS-SupersededServiceAccountState"],
            )
        ],
    )
    paths = classify_paths(state)
    assert paths
    assert paths[0].primitive == "postpatch-mutual-pair"


def test_existing_dmsa_postpatch_classifier_requires_target_attrs():
    state = MapState(
        environment=Environment(dmsa_capable=True),
        schema_cache=SchemaCache(),
        dmsas=[
            DmsaObject(
                dn="CN=dmsa,CN=Managed Service Accounts,DC=corp,DC=local",
                rights=[Right(principal_sid="S-1-5-21-X-1000", right="GenericWrite", object_dn="CN=dmsa,CN=Managed Service Accounts,DC=corp,DC=local")],
            )
        ],
        targets=[
            TargetObject(
                dn="CN=svc,CN=Users,DC=corp,DC=local",
                writable_attrs=[
                    "msDS-SupersededManagedAccountLink",
                    "msDS-SupersededServiceAccountState",
                ],
            )
        ],
    )
    paths = classify_paths(state)
    assert paths
    assert paths[0].primitive == "existing-dmsa-postpatch-mutual"
