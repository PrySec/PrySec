using System.Runtime.CompilerServices;

namespace PrySec.Core.ArrayTypes;

public unsafe readonly struct Array2d<T> where T : unmanaged
{
	public readonly int Rows;
	public readonly int Columns;
	private readonly T* _basePointer;

	public Array2d(T* ptr, int rows, int columns)
	{
		_basePointer = ptr;
		Rows = rows;
		Columns = columns;
	}

    public T this[int row, int column]
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => this[(uint)row, (uint)column];

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        set => this[(uint)row, (uint)column] = value;
    }

    public T this[uint row, uint column]
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        get => _basePointer[Columns * row + column];

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        set => _basePointer[Columns * row + column] = value;
    }

    public static implicit operator T*(Array2d<T> array) => array._basePointer;
}
