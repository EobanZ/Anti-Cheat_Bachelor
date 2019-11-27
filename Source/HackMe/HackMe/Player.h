#pragma once
#include "Character.h"
#include <iostream>
#include <Windows.h>
class Vector2 {

public:
	Vector2(int x = 0, int y = 0);
	int X;
	int Y;

};
class Player : public Character
{
public:
	Player();
	~Player();
	void applyDamage(int t_amount);
	void attack();
	void drinkManaPotion();
	int getHealth();
	int getMana();
	void moveUp();
	void moveRight();
	void moveLeft();
	void moveDown();
	Vector2 getPos();
	virtual int virtualFunctionToHook(int arg1) override;


private:
	int m_health;
	int m_mana;
	Vector2 m_pos;
	

};

