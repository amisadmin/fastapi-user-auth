from fastapi_amis_admin.crud import CrudEnum

from fastapi_user_auth.auth import Auth


async def test_casbin(fake_auth: Auth):
    # await fake_auth.enforcer.add_policy("casbin", "87db042b14a5b555", "dfwe")
    await fake_auth.enforcer.add_policy("casbin", "87db042b14a5b555", "update")
    print("enforcer", fake_auth.enforcer.enforce("casbin", "87db042b14a5b555", CrudEnum.update))
    print("enforcer", fake_auth.enforcer.enforce("casbin", "87db042b14a5b555", "update"))
