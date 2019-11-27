#include "pch.h"
#include "Player.h"


Player::Player() : m_health(100), m_mana(10), m_pos(Vector2(0, 0))
{
}


Player::~Player()
{
}

void Player::applyDamage(int t_amount)
{
	m_health -= t_amount;
	if (m_health < 0)
	{
		m_health = 0;
	}
}

void Player::attack()
{
	--m_mana;
	m_mana = m_mana < 0 ? 0 : m_mana;
}

void Player::drinkManaPotion()
{
	m_mana = 10;
}

int Player::getHealth()
{
	return m_health;
}

int Player::getMana()
{
	return m_mana;
}

void Player::moveUp()
{
	m_pos.Y++;
}

void Player::moveRight()
{
	m_pos.X++;
}

void Player::moveLeft()
{
	m_pos.X--;
}

void Player::moveDown()
{
	m_pos.Y--;
}

Vector2 Player::getPos()
{
	return m_pos;
}

int Player::virtualFunctionToHook(int arg1)
{
	if (arg1 != 1337) {
		printf_s("Virtual Function Table Hook Worked!");
		Sleep(5000);
	}
	else
	{
		printf_s("VFT Hook dind't work\n");
	}
	return 0;
}

Vector2::Vector2(int x, int y)
{
	X = x;
	Y = y;
}
