
#include "pch.h"
#include <iostream>
#include <Windows.h>
#include "Player.h"

//Globale Variable, damit Adresse sich nicht ändert.
//Nach jedem Kompiliervorgang muss die Adresse im internen Cheat für den VFT Hook neu eingetragen werden.
Player player; 
Character* character = (Character*)&player; //To test VFT Hook

int main(int argc, TCHAR *argv[])
{
	SetConsoleTitle(L"HackMe");
	
	static unsigned int ticks = 0;
	static bool started = false;


	std::cout << "Press insert to start the game tick" << std::endl;

	while (!started)
	{
		if (GetAsyncKeyState(VK_INSERT) & 1)
		{
			started = true;
		}
		Sleep(100);
	}

	while (true && !GetAsyncKeyState(VK_ESCAPE))
	{
		system("CLS");
		std::cout << "Tick: " << std::dec << ticks << std::endl;
		++ticks;
		std::cout << std::dec <<"Player health: " << player.getHealth() << " Mana: " << player.getMana() << std::endl;
		std::cout << "F1: Attack  F2: GetDamage  F3: Drink Mana Potion" << std::endl << "Use arrow keys to move position" << std::endl;
		std::cout << "F4: Test if sleep is hooked (IAT Hook)" << std::endl << "F5: Test if VF is Hooked (VFT Hook)" << std::endl;
		std::cout << std::dec << "Position: X->" << player.getPos().X << " Y->" << player.getPos().Y << std::endl;

		

		if (GetAsyncKeyState(VK_F1) & 1)
		{
			player.attack();
		}
		if (GetAsyncKeyState(VK_F2) & 1)
		{
			player.applyDamage(10);
		}
		if (GetAsyncKeyState(VK_F3) & 1)
		{
			player.drinkManaPotion();
		}
		if (GetAsyncKeyState(VK_UP) & 1)
		{
			player.moveUp();
		}
		if (GetAsyncKeyState(VK_DOWN) & 1)
		{
			player.moveDown();
		}
		if (GetAsyncKeyState(VK_LEFT) & 1)
		{
			player.moveLeft();
		}
		if (GetAsyncKeyState(VK_RIGHT) & 1)
		{
			player.moveRight();
		}
		if (GetAsyncKeyState(VK_F4) & 1)
		{
			Sleep(1337);
		}
		if (GetAsyncKeyState(VK_F5) & 1)
		{
			character->virtualFunctionToHook(1337);
		}
		
		Sleep(100);
	}

	getchar();
}

