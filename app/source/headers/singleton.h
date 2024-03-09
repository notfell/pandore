#pragma once

template <typename T>
class singleton
{
	public:
		static T* get()
		{
			static T instance;
			return &instance;
		}
};
