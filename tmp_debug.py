import asyncio
from runtime.runtime import get_runtime
from tests.conftest import make_mission
from domain.mission import MissionTarget, MissionType

runtime = get_runtime()
runtime.mission_manager._missions.clear()
runtime.state_manager._states.clear()

async def main():
    print('before create')
    mission = await runtime.mission_manager.create_mission(
        name='dbg', mission_type=MissionType.EXTERNAL_ATTACK_SURFACE,
        target=MissionTarget(domains=['x.test']),
        description='dbg', priority='high'
    )
    print('after create', mission.id)
    await runtime.state_manager.initialize_mission_state(mission)
    print('after init')

asyncio.run(main())
print('done')
